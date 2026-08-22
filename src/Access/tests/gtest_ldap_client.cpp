#include <Access/LDAPClient.h>
#include <Common/SipHash.h>

#include <gtest/gtest.h>

using namespace DB;

namespace
{
class TestLDAPClient : public LDAPClient
{
public:
    using LDAPClient::escapeForDN;
};

UInt128 getHash(const LDAPClient::Params & params)
{
    SipHash hash;
    params.updateHash(hash);
    return hash.get128();
}
}

TEST(LDAPClient, EscapesDNDistinguishedValueBoundaries)
{
    String value = " user,";
    value.push_back('\0');
    value += "name ";

    EXPECT_EQ(TestLDAPClient::escapeForDN(value), "\\ user\\,\\00name\\ ");
    EXPECT_EQ(TestLDAPClient::escapeForDN("line\nbreak"), "line\\0Abreak");
    EXPECT_EQ(TestLDAPClient::escapeForDN("#leading"), "\\#leading");
    EXPECT_EQ(TestLDAPClient::escapeForDN("middle#hash"), "middle#hash");
}

TEST(LDAPClient, AuthenticationPolicyParticipatesInParamsHash)
{
    LDAPClient::Params params;
    params.host = "ldap.example.test";
    params.bind_dn = "uid={user_name},dc=example,dc=test";
    params.user = "user";
    params.password = "password";

    const auto original_hash = getHash(params);

    params.enable_tls = LDAPClient::Params::TLSEnable::NO;
    EXPECT_NE(getHash(params), original_hash);

    params.enable_tls = LDAPClient::Params::TLSEnable::YES;
    params.tls_require_cert = LDAPClient::Params::TLSRequireCert::NEVER;
    EXPECT_NE(getHash(params), original_hash);

    params.tls_require_cert = LDAPClient::Params::TLSRequireCert::DEMAND;
    params.search_limit += 1;
    EXPECT_NE(getHash(params), original_hash);
}
