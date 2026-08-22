#include <Access/AccessControl.h>
#include <Access/Quota.h>
#include <Access/Role.h>
#include <Access/RowPolicy.h>
#include <Access/SettingsProfile.h>
#include <Access/User.h>
#include <Access/UsersConfigAccessStorage.h>
#include <gtest/gtest.h>
#include <Poco/TemporaryFile.h>
#include <Poco/Util/XMLConfiguration.h>
#include <Common/Exception.h>

#include <fstream>
#include <sstream>

using namespace DB;

namespace
{
    Poco::AutoPtr<Poco::Util::XMLConfiguration> createConfigFromXML(const std::string & xml_content)
    {
        std::istringstream xml_stream(xml_content);
        Poco::AutoPtr<Poco::Util::XMLConfiguration> config = new Poco::Util::XMLConfiguration(xml_stream);
        return config;
    }
}

class UsersConfigMultipleAuthTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        access_control = std::make_unique<AccessControl>();
        storage = std::make_unique<UsersConfigAccessStorage>("users_config_test", *access_control, false);
    }

    std::unique_ptr<AccessControl> access_control;
    std::unique_ptr<UsersConfigAccessStorage> storage;
};

TEST_F(UsersConfigMultipleAuthTest, SinglePlaintextPassword)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <password>plaintext_pass</password>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);
    
    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::PLAINTEXT_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, UndefinedRoleGrantIsNotRetained)
{
    const auto config = createConfigFromXML(R"(
        <clickhouse>
            <users>
                <test_user>
                    <password></password>
                    <grants>
                        <query>GRANT missing_role</query>
                    </grants>
                </test_user>
            </users>
        </clickhouse>
    )");

    storage->setConfig(*config);

    const auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    EXPECT_TRUE(user->granted_roles.getGranted().empty());
}

TEST_F(UsersConfigMultipleAuthTest, DottedEntityNamesUseUnescapedIDs)
{
    const auto config = createConfigFromXML(R"(
        <clickhouse>
            <roles>
                <role.with.dot/>
            </roles>
            <profiles>
                <profile.with.dot>
                    <max_threads>1</max_threads>
                </profile.with.dot>
            </profiles>
            <quotas>
                <quota.with.dot>
                    <interval>
                        <duration>60</duration>
                        <queries>10</queries>
                    </interval>
                </quota.with.dot>
            </quotas>
            <users>
                <test_user>
                    <password></password>
                    <profile>profile.with.dot</profile>
                    <quota>quota.with.dot</quota>
                    <grants>
                        <query>GRANT `role.with.dot`</query>
                    </grants>
                </test_user>
            </users>
        </clickhouse>
    )");

    storage->setConfig(*config);

    const auto role_id = storage->find<Role>("role.with.dot");
    const auto profile_id = storage->find<SettingsProfile>("profile.with.dot");
    const auto user_id = storage->find<User>("test_user");
    const auto role = storage->tryRead<Role>("role.with.dot");
    const auto profile = storage->tryRead<SettingsProfile>("profile.with.dot");
    const auto quota = storage->tryRead<Quota>("quota.with.dot");
    const auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(role);
    ASSERT_TRUE(profile);
    ASSERT_TRUE(quota);
    ASSERT_TRUE(user);
    ASSERT_TRUE(role_id);
    ASSERT_TRUE(profile_id);
    ASSERT_TRUE(user_id);
    EXPECT_TRUE(user->granted_roles.isGranted(*role_id));
    EXPECT_EQ(user->settings.toProfileIDs(), UUIDs{*profile_id});
    EXPECT_TRUE(quota->to_roles.match(*user_id));
}

#if USE_SSL
TEST_F(UsersConfigMultipleAuthTest, EmptySSLCertificateListIsRejected)
{
    const auto config = createConfigFromXML(R"(
        <clickhouse>
            <users>
                <test_user><ssl_certificates/></test_user>
            </users>
        </clickhouse>
    )");

    EXPECT_THROW(storage->setConfig(*config), Exception);
}
#endif

TEST(UsersConfigAccessStorage, ReplacementDeliversNotifications)
{
    auto initial_config = createConfigFromXML(R"(
        <clickhouse>
            <users>
                <initial_user><no_password/></initial_user>
            </users>
        </clickhouse>
    )");
    auto replacement_config = createConfigFromXML(R"(
        <clickhouse>
            <users>
                <replacement_user><no_password/></replacement_user>
            </users>
        </clickhouse>
    )");

    AccessControl access_control;
    access_control.addUsersConfigStorage("users_config_test", *initial_config, false);

    bool replacement_visible_during_notification = false;
    auto subscription = access_control.subscribeForChanges<User>(
        [&](const std::vector<AccessChangesNotifier::Change> & changes)
        {
            if (!changes.empty())
                replacement_visible_during_notification = access_control.find<User>("replacement_user").has_value();
        });

    access_control.setUsersConfig(*replacement_config);

    EXPECT_TRUE(replacement_visible_during_notification);
}

TEST(UsersConfigAccessStorage, ReloadCallbackOwnsConfigPath)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String config_path = temp_dir.path() + "/users.xml";

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <initial_user><no_password/></initial_user>
            </users>
        </clickhouse>
    )";

    AccessControl access_control;
    UsersConfigAccessStorage storage("users_config_test", access_control, false);
    storage.load(config_path, "", temp_dir.path(), [] { return zkutil::ZooKeeperPtr{}; });

    const String original_config_path = config_path;
    config_path = "mutated-after-load.xml";
    std::ofstream{original_config_path} << R"(
        <clickhouse>
            <max_threads>1</max_threads>
        </clickhouse>
    )";

    try
    {
        storage.reload(IAccessStorage::ReloadMode::ALL);
        FAIL() << "reload unexpectedly succeeded";
    }
    catch (const Exception & e)
    {
        EXPECT_NE(e.message().find(original_config_path), String::npos);
        EXPECT_EQ(e.message().find(config_path), String::npos);
    }
}

TEST(UsersConfigAccessStorage, ReloadNotificationHandlerCanReadPath)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    const String config_path = temp_dir.path() + "/users.xml";

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <initial_user><no_password/></initial_user>
            </users>
        </clickhouse>
    )";

    AccessControl access_control;
    UsersConfigAccessStorage storage("users_config_test", access_control, false);
    storage.load(config_path, "", temp_dir.path(), [] { return zkutil::ZooKeeperPtr{}; });
    access_control.getChangesNotifier().sendNotifications();

    bool path_was_read = false;
    auto subscription = access_control.subscribeForChanges<User>(
        [&](const std::vector<AccessChangesNotifier::Change> & changes)
        {
            if (!changes.empty())
                path_was_read = (storage.getPath() == config_path);
        });

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <replacement_user><no_password/></replacement_user>
            </users>
        </clickhouse>
    )";

    storage.reload(IAccessStorage::ReloadMode::ALL);
    EXPECT_TRUE(path_was_read);
}

TEST(UsersConfigAccessStorage, InvalidDirectConfigPreservesFileReloader)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    const String config_path = temp_dir.path() + "/users.xml";

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <initial_user><no_password/></initial_user>
            </users>
        </clickhouse>
    )";

    AccessControl access_control;
    UsersConfigAccessStorage storage("users_config_test", access_control, false);
    storage.load(config_path, "", temp_dir.path(), [] { return zkutil::ZooKeeperPtr{}; });

    auto invalid_config = createConfigFromXML(R"(
        <clickhouse>
            <users>
                <invalid_user>
                    <http_authentication>
                        <server>http_auth_server</server>
                    </http_authentication>
                </invalid_user>
            </users>
        </clickhouse>
    )");
    EXPECT_THROW(storage.setConfig(*invalid_config), Exception);
    EXPECT_EQ(config_path, storage.getPath());

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <replacement_user><no_password/></replacement_user>
            </users>
        </clickhouse>
    )";
    storage.reload(IAccessStorage::ReloadMode::ALL);

    EXPECT_FALSE(storage.find<User>("initial_user").has_value());
    EXPECT_TRUE(storage.find<User>("replacement_user").has_value());
}

TEST(UsersConfigAccessStorage, InvalidFileReplacementPreservesFileReloader)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    const String config_path = temp_dir.path() + "/users.xml";
    const String invalid_config_path = temp_dir.path() + "/invalid-users.xml";

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <initial_user><no_password/></initial_user>
            </users>
        </clickhouse>
    )";
    std::ofstream{invalid_config_path} << R"(
        <clickhouse>
            <max_threads>1</max_threads>
        </clickhouse>
    )";

    AccessControl access_control;
    UsersConfigAccessStorage storage("users_config_test", access_control, false);
    storage.load(config_path, "", temp_dir.path(), [] { return zkutil::ZooKeeperPtr{}; });

    EXPECT_THROW(storage.load(invalid_config_path, "", temp_dir.path(), [] { return zkutil::ZooKeeperPtr{}; }), Exception);
    EXPECT_EQ(config_path, storage.getPath());

    std::ofstream{config_path} << R"(
        <clickhouse>
            <users>
                <replacement_user><no_password/></replacement_user>
            </users>
        </clickhouse>
    )";
    storage.reload(IAccessStorage::ReloadMode::ALL);

    EXPECT_FALSE(storage.find<User>("initial_user").has_value());
    EXPECT_TRUE(storage.find<User>("replacement_user").has_value());
}

TEST_F(UsersConfigMultipleAuthTest, DottedUserNameKeepsQuotaAndRowPolicyAssignments)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <user.name>
                    <no_password/>
                    <quota>default</quota>
                    <databases>
                        <database>
                            <table>
                                <filter>value = 1</filter>
                            </table>
                        </database>
                    </databases>
                </user.name>
            </users>
            <quotas>
                <default/>
            </quotas>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user_id = storage->find<User>("user.name");
    ASSERT_TRUE(user_id.has_value());

    auto quota = storage->tryRead<Quota>("default");
    ASSERT_TRUE(quota);
    EXPECT_TRUE(quota->to_roles.match(*user_id));

    auto policies = storage->readAllWithIDs<RowPolicy>();
    ASSERT_EQ(policies.size(), 1);
    EXPECT_EQ(policies.front().second->getShortName(), "user.name");
    EXPECT_TRUE(policies.front().second->to_roles.match(*user_id));
}

TEST_F(UsersConfigMultipleAuthTest, FlatNoPassword)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <no_password/>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::NO_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, MultiplePlaintextPasswords)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><password>plaintext_pass1</password></a1>
                        <a2><password>plaintext_pass2</password></a2>
                        <a3><password>plaintext_pass3</password></a3>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 3);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::PLAINTEXT_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleSHA256Passwords)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><password_sha256_hex>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</password_sha256_hex></a1>
                        <a2><password_sha256_hex>d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2</password_sha256_hex></a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::SHA256_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleDoubleSHA1Passwords)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><password_double_sha1_hex>eafbd9c4b3c8b40d509308e767b41671ee5bac68</password_double_sha1_hex></a1>
                        <a2><password_double_sha1_hex>7e4ca4bb0df85c1106f39516a0753013b79b32ff</password_double_sha1_hex></a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::DOUBLE_SHA1_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleLDAPServers)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><ldap><server>ldap_server_1</server></ldap></a1>
                        <a2><ldap><server>ldap_server_2</server></ldap></a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::LDAP);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleKerberosRealms)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><kerberos><realm>EXAMPLE.COM</realm></kerberos></a1>
                        <a2><kerberos><realm>TEST.ORG</realm></kerberos></a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::KERBEROS);
}

TEST_F(UsersConfigMultipleAuthTest, KerberosWithoutRealm)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <kerberos/>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::KERBEROS);
    EXPECT_EQ(user->authentication_methods[0].getKerberosRealm(), "");
}

TEST_F(UsersConfigMultipleAuthTest, SingleHTTPAuthentication)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication>
                        <server>http_auth_server</server>
                        <scheme>basic</scheme>
                    </http_authentication>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);
    
    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::HTTP);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleHTTPAuthenticationMethods)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><http_authentication><server>http_auth_server_1</server><scheme>basic</scheme></http_authentication></a1>
                        <a2><http_authentication><server>http_auth_server_2</server><scheme>basic</scheme></http_authentication></a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);

    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::HTTP);
}

TEST_F(UsersConfigMultipleAuthTest, SingleHTTPAuthenticationWithWrapper)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <method1>
                            <http_authentication>
                                <server>http_auth_server</server>
                                <scheme>basic</scheme>
                            </http_authentication>
                        </method1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::HTTP);
    EXPECT_EQ(user->authentication_methods[0].getHTTPAuthenticationServerName(), "http_auth_server");
    EXPECT_EQ(user->authentication_methods[0].getHTTPAuthenticationScheme(), HTTPAuthenticationScheme::BASIC);
}

TEST_F(UsersConfigMultipleAuthTest, HTTPAuthenticationMissingSchemeError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication>
                        <server>http_auth_server</server>
                    </http_authentication>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, HTTPAuthenticationMissingServerError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication>
                        <scheme>basic</scheme>
                    </http_authentication>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, HTTPAuthenticationEmptyError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication/>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, HTTPAuthenticationNestedMethodsWithoutServerSchemeError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication>
                        <method1>
                            <server>http_auth_server</server>
                            <scheme>basic</scheme>
                        </method1>
                    </http_authentication>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, MultipleHTTPAuthenticationMissingSchemeError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1>
                            <http_authentication>
                                <server>http_auth_server_1</server>
                                <scheme>basic</scheme>
                            </http_authentication>
                        </a1>
                        <a2>
                            <http_authentication>
                                <server>http_auth_server_2</server>
                            </http_authentication>
                        </a2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, HTTPAuthenticationMixedSyntax)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <http_authentication>
                        <server>primary_server</server>
                        <scheme>basic</scheme>
                        <method1>
                            <server>other_server</server>
                            <scheme>basic</scheme>
                        </method1>
                    </http_authentication>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);
    
    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    // When un-nested server/scheme are present other http authn methods are ignored
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getHTTPAuthenticationServerName(), "primary_server");
    EXPECT_EQ(user->authentication_methods[0].getHTTPAuthenticationScheme(), HTTPAuthenticationScheme::BASIC);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::HTTP);
}

TEST_F(UsersConfigMultipleAuthTest, MixedAuthenticationMethods)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1><password>plaintext_pass1</password></a1>
                        <a2><password>plaintext_pass2</password></a2>
                        <a3><password_sha256_hex>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</password_sha256_hex></a3>
                        <a4><ldap><server>ldap_server_1</server></ldap></a4>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 4);

    int plaintext_count = 0;
    int sha256_count = 0;
    int ldap_count = 0;

    for (const auto & auth_method : user->authentication_methods)
    {
        switch (auth_method.getType())
        {
            case AuthenticationType::PLAINTEXT_PASSWORD: 
                plaintext_count++; 
                break;
            case AuthenticationType::SHA256_PASSWORD:    
                sha256_count++;    
                break;
            case AuthenticationType::LDAP:               
                ldap_count++;      
                break;
            default: 
                FAIL() << "Unexpected authentication type";
        }
    }

    EXPECT_EQ(plaintext_count, 2);
    EXPECT_EQ(sha256_count, 1);
    EXPECT_EQ(ldap_count, 1);
}

// ---------------------------------------------------------------------------
// Nested auth_methods format tests
// ---------------------------------------------------------------------------

TEST_F(UsersConfigMultipleAuthTest, NestedNoPasswordInAuthMethods)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <auth1>
                            <no_password/>
                        </auth1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::NO_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, NestedNoPasswordInMultipleAuthMethodsIsDisallowed)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <auth1>
                            <no_password/>
                        </auth1>
                        <auth2>
                            <password>plaintext_pass1</password>
                        </auth2>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, EmptyAuthMethodsIsDisallowed)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods/>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, OTPInsideAuthMethodIsDisallowed)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1>
                            <time_based_one_time_password>
                                <secret>JBSWY3DPEHPK3PXP</secret>
                            </time_based_one_time_password>
                            <password>plaintext_pass1</password>
                        </a1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, NestedSinglePlaintextPassword)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <auth1>
                            <password>plaintext_pass</password>
                        </auth1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::PLAINTEXT_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, NestedMultiplePlaintextPasswords)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <auth1>
                            <password>pass1</password>
                        </auth1>
                        <auth2>
                            <password>pass2</password>
                        </auth2>
                        <auth3>
                            <password>pass3</password>
                        </auth3>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 3);
    for (const auto & auth_method : user->authentication_methods)
        EXPECT_EQ(auth_method.getType(), AuthenticationType::PLAINTEXT_PASSWORD);
}

TEST_F(UsersConfigMultipleAuthTest, NestedMixedAuthenticationTypes)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <plain>
                            <password>plaintext_pass</password>
                        </plain>
                        <sha256>
                            <password_sha256_hex>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</password_sha256_hex>
                        </sha256>
                        <double_sha1>
                            <password_double_sha1_hex>eafbd9c4b3c8b40d509308e767b41671ee5bac68</password_double_sha1_hex>
                        </double_sha1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 3);

    int plaintext_count = 0;
    int sha256_count = 0;
    int double_sha1_count = 0;
    for (const auto & auth_method : user->authentication_methods)
    {
        switch (auth_method.getType())
        {
            case AuthenticationType::PLAINTEXT_PASSWORD: 
                plaintext_count++; 
                break;
            case AuthenticationType::SHA256_PASSWORD:    
                sha256_count++;    
                break;
            case AuthenticationType::DOUBLE_SHA1_PASSWORD: 
                double_sha1_count++; 
                break;
            default: 
                FAIL() << "Unexpected authentication type";
        }
    }
    EXPECT_EQ(plaintext_count, 1);
    EXPECT_EQ(sha256_count, 1);
    EXPECT_EQ(double_sha1_count, 1);
}

TEST_F(UsersConfigMultipleAuthTest, NestedLDAPAuthentication)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <ldap_method>
                            <ldap>
                                <server>my_ldap_server</server>
                            </ldap>
                        </ldap_method>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 1);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::LDAP);
    EXPECT_EQ(user->authentication_methods[0].getLDAPServerName(), "my_ldap_server");
}

TEST_F(UsersConfigMultipleAuthTest, NestedAndFlatFormatsCannotBeMixed)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <password>some_password</password>
                    <auth_methods>
                        <auth1>
                            <password>another_password</password>
                        </auth1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, NestedMultipleTypesPerMethodIsError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <auth1>
                            <password>pass</password>
                            <password_sha256_hex>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</password_sha256_hex>
                        </auth1>
                    </auth_methods>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, OTPWithNonPasswordAuthIsError)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1>
                            <ldap><server>ldap_server_1</server></ldap>
                        </a1>
                    </auth_methods>
                    <time_based_one_time_password>
                        <secret>JBSWY3DPEHPK3PXP</secret>
                    </time_based_one_time_password>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    EXPECT_THROW(storage->setConfig(*config), Exception);
}

TEST_F(UsersConfigMultipleAuthTest, OTPWithMixedAuthIncludingPassword)
{
    const std::string xml_config = R"(
        <clickhouse>
            <users>
                <test_user>
                    <auth_methods>
                        <a1>
                            <ldap><server>ldap_server_1</server></ldap>
                        </a1>
                        <a2>
                            <password>plaintext_pass</password>
                        </a2>
                    </auth_methods>
                    <time_based_one_time_password>
                        <secret>JBSWY3DPEHPK3PXP</secret>
                    </time_based_one_time_password>
                </test_user>
            </users>
        </clickhouse>
    )";

    auto config = createConfigFromXML(xml_config);
    storage->setConfig(*config);

    auto user = storage->tryRead<User>("test_user");
    ASSERT_TRUE(user);
    ASSERT_EQ(user->authentication_methods.size(), 2);
    EXPECT_EQ(user->authentication_methods[0].getType(), AuthenticationType::LDAP);
    EXPECT_EQ(user->authentication_methods[1].getType(), AuthenticationType::PLAINTEXT_PASSWORD);
}
