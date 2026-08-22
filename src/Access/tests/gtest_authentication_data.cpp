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

TEST(AuthenticationData, ScramPasswordHashMustHaveSHA256Length)
{
    AuthenticationData authentication_data{AuthenticationType::SCRAM_SHA256_PASSWORD};

    EXPECT_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(31), std::nullopt, false), Exception);
    EXPECT_NO_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(32), std::nullopt, false));
    EXPECT_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(33), std::nullopt, false), Exception);
}

TEST(AuthenticationData, InvalidHashDoesNotChangeSecondFactor)
{
    AuthenticationData authentication_data{AuthenticationType::SCRAM_SHA256_PASSWORD};
    authentication_data.setPasswordHashBinary(
        AuthenticationData::Digest(32), OneTimePasswordSecret{"JBSWY3DPEHPK3PXP"}, true);
    const auto original = authentication_data;

    EXPECT_THROW(
        authentication_data.setPasswordHashBinary(
            AuthenticationData::Digest(31), OneTimePasswordSecret{"JBSWY3DPEHPK3PXQ"}, true),
        Exception);
    EXPECT_EQ(authentication_data, original);
}

TEST(Authentication, OneTimePasswordRejectsNonASCIIBytes)
{
    const OneTimePasswordSecret secret{"JBSWY3DPEHPK3PXP"};
    String password(secret.params.num_digits, '1');
    password.front() = static_cast<char>(0xFF);

    EXPECT_FALSE(checkOneTimePassword(password, secret));
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

TEST(Authentication, ScramCredentialsCompareCompleteProof)
{
    const std::string auth_message = "auth-message";
    const AuthenticationData::Digest salted_password(32);
    const auto client_key = hmacSHA256(salted_password, "Client Key");
    const auto stored_key = encodeSHA256(client_key);
    const auto client_signature = hmacSHA256(stored_key, auth_message);

    String client_proof(client_key.size(), 0);
    for (size_t i = 0; i != client_key.size(); ++i)
        client_proof[i] = client_key[i] ^ client_signature[i];
    const auto encoded_proof = base64Encode(client_proof);

    AuthenticationData authentication_data{AuthenticationType::SCRAM_SHA256_PASSWORD};
    authentication_data.setPasswordHashBinary(salted_password, std::nullopt, true);
    ExternalAuthenticators external_authenticators;
    ClientInfo client_info;
    SettingsChanges settings;

    auto check = [&](String proof)
    {
        ScramSHA256Credentials credentials{"user", proof, auth_message, 4096};
        return Authentication::areCredentialsValid(
            credentials, authentication_data, external_authenticators, client_info, settings);
    };

    EXPECT_EQ(check(encoded_proof), Authentication::CredentialsCheckResult::Success);

    String wrong_first_byte = encoded_proof;
    wrong_first_byte.front() ^= 1;
    EXPECT_EQ(check(wrong_first_byte), Authentication::CredentialsCheckResult::Fail);

    String wrong_last_byte = encoded_proof;
    wrong_last_byte.back() ^= 1;
    EXPECT_EQ(check(wrong_last_byte), Authentication::CredentialsCheckResult::Fail);
}
#endif
