#include <Access/Authentication.h>
#include <Access/AuthenticationData.h>
#include <Access/Common/OneTimePassword.h>
#include <Access/Credentials.h>
#include <Access/ExternalAuthenticators.h>
#include <Common/Base64.h>
#include <Common/OpenSSLHelpers.h>
#include <Common/SettingsChanges.h>
#include <Interpreters/ClientInfo.h>
#include <gtest/gtest.h>

using namespace DB;

TEST(AuthenticationData, SaltParticipatesInEquality)
{
    AuthenticationData first{AuthenticationType::SHA256_PASSWORD};
    first.setPasswordHashBinary(AuthenticationData::Digest(32), std::nullopt, true);
    first.setSalt("first");

    AuthenticationData second = first;
    second.setSalt("second");

    EXPECT_NE(first, second);
}

TEST(AuthenticationData, OneTimePasswordParticipatesInEquality)
{
    AuthenticationData first{AuthenticationType::NO_PASSWORD};
    first.setPassword("", OneTimePasswordSecret{"JBSWY3DPEHPK3PXP"}, true);

    AuthenticationData second{AuthenticationType::NO_PASSWORD};
    second.setPassword("", OneTimePasswordSecret{"JBSWY3DPEHPK3PXQ"}, true);

    EXPECT_NE(first, second);
}

TEST(AuthenticationData, NoAuthenticationRoundTripPreservesValidUntil)
{
    AuthenticationData original{AuthenticationType::NO_AUTHENTICATION};
    original.setValidUntil(1'800'000'000);

    const auto ast = original.toAST();
    const auto restored = AuthenticationData::fromAST(*ast, nullptr, false);

    EXPECT_EQ(restored.getValidUntil(), original.getValidUntil());
}

#if USE_SSL
TEST(Authentication, ScramCredentialsRejectOtherAuthenticationTypes)
{
    const std::string auth_message = "auth-message";
    const auto client_key = hmacSHA256({}, "Client Key");
    const auto stored_key = encodeSHA256(client_key);
    const auto client_signature = hmacSHA256(stored_key, auth_message);

    String client_proof(client_key.size(), 0);
    for (size_t i = 0; i != client_key.size(); ++i)
        client_proof[i] = client_key[i] ^ client_signature[i];

    ScramSHA256Credentials credentials{"user", base64Encode(client_proof), auth_message, 4096};
    AuthenticationData no_authentication{AuthenticationType::NO_AUTHENTICATION};
    ExternalAuthenticators external_authenticators;
    ClientInfo client_info;
    SettingsChanges settings;

    EXPECT_EQ(
        Authentication::areCredentialsValid(credentials, no_authentication, external_authenticators, client_info, settings),
        Authentication::CredentialsCheckResult::Fail);
}
#endif
