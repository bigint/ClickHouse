#include <Access/ExternalAuthenticators.h>
#include <Common/Exception.h>
#include <Common/Logger.h>

#include <gtest/gtest.h>
#include <Poco/AutoPtr.h>
#include <Poco/Util/XMLConfiguration.h>

#include <sstream>
#include <stdexcept>


namespace DB
{

struct ExternalAuthenticatorsTestAccess
{
    static HTTPAuthClientParams getHTTPAuthenticationParams(const ExternalAuthenticators & authenticators, const String & server)
    {
        return authenticators.getHTTPAuthenticationParams(server);
    }

    static LDAPClient::Params getLDAPParams(const ExternalAuthenticators & authenticators, const String & server)
    {
        std::lock_guard lock(authenticators.mutex);
        return authenticators.ldap_client_params_blueprint.at(server);
    }
};

namespace
{
    Poco::AutoPtr<Poco::Util::XMLConfiguration> createConfig(const String & xml)
    {
        std::istringstream stream(xml);
        Poco::AutoPtr<Poco::Util::XMLConfiguration> config = new Poco::Util::XMLConfiguration(stream);
        return config;
    }
}

TEST(ExternalAuthenticators, ResetRemovesHTTPServers)
{
    ExternalAuthenticators authenticators;
    const auto config = createConfig(R"(
        <clickhouse>
            <http_authentication_servers>
                <primary>
                    <uri>http://127.0.0.1:1/authenticate</uri>
                </primary>
            </http_authentication_servers>
        </clickhouse>
    )");
    authenticators.setConfiguration(*config, getLogger("ExternalAuthenticatorsResetTest"));
    EXPECT_EQ(
        ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary").uri.toString(),
        "http://127.0.0.1:1/authenticate");

    authenticators.reset();
    EXPECT_THROW(ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary"), Exception);
}

TEST(ExternalAuthenticators, FailedReloadPreservesPreviousConfiguration)
{
    ExternalAuthenticators authenticators;
    const auto valid_config = createConfig(R"(
        <clickhouse>
            <http_authentication_servers>
                <primary>
                    <uri>http://127.0.0.1:1/authenticate</uri>
                </primary>
            </http_authentication_servers>
        </clickhouse>
    )");
    authenticators.setConfiguration(*valid_config, getLogger("ExternalAuthenticatorsReloadTest"));

    const auto invalid_config = createConfig(R"(
        <clickhouse>
            <http_authentication_servers/>
            <http_authentication_servers/>
        </clickhouse>
    )");
    EXPECT_THROW(authenticators.setConfiguration(*invalid_config, getLogger("ExternalAuthenticatorsReloadTest")), Exception);

    EXPECT_EQ(
        ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary").uri.toString(),
        "http://127.0.0.1:1/authenticate");
}

TEST(ExternalAuthenticators, RejectsInitialBackoffAboveMaximum)
{
    ExternalAuthenticators authenticators;
    const auto config = createConfig(R"(
        <clickhouse>
            <http_authentication_servers>
                <primary>
                    <uri>http://127.0.0.1:1/authenticate</uri>
                    <retry_initial_backoff_ms>1001</retry_initial_backoff_ms>
                    <retry_max_backoff_ms>1000</retry_max_backoff_ms>
                </primary>
            </http_authentication_servers>
        </clickhouse>
    )");
    authenticators.setConfiguration(*config, getLogger("ExternalAuthenticatorsBackoffTest"));

    EXPECT_THROW(ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary"), Exception);
}

TEST(ExternalAuthenticators, RejectsLDAPSearchLimitAboveAPIRange)
{
    ExternalAuthenticators authenticators;
    const auto config = createConfig(R"(
        <clickhouse>
            <ldap_servers>
                <primary>
                    <host>127.0.0.1</host>
                    <search_limit>2147483648</search_limit>
                </primary>
            </ldap_servers>
        </clickhouse>
    )");
    authenticators.setConfiguration(*config, getLogger("ExternalAuthenticatorsLDAPLimitTest"));

    EXPECT_THROW(ExternalAuthenticatorsTestAccess::getLDAPParams(authenticators, "primary"), std::out_of_range);
}

}
