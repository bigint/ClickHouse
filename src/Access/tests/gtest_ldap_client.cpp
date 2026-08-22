#include <Access/LDAPClient.h>
#include <Common/SipHash.h>

#include <gtest/gtest.h>

using namespace DB;

namespace
{
UInt128 getHash(const LDAPClient::Params & params)
{
    SipHash hash;
    params.updateHash(hash);
    return hash.get128();
}
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
