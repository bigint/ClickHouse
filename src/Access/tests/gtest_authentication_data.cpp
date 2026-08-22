#include <Access/Authentication.h>
#include <Access/AuthenticationData.h>
#include <Access/Common/OneTimePassword.h>
#include <Access/Credentials.h>
#include <Access/ExternalAuthenticators.h>
#include <Common/Base64.h>
#include <Common/OpenSSLHelpers.h>
#include <Common/SettingsChanges.h>
#include <Interpreters/ClientInfo.h>
#include <Parsers/ASTLiteral.h>
#include <Poco/SHA1Engine.h>
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

TEST(AuthenticationData, ValidUntilRejectsTrailingCharacters)
{
    ASTAuthenticationData ast;
    ast.type = AuthenticationType::NO_AUTHENTICATION;
    ast.valid_until = make_intrusive<ASTLiteral>(String{"2026-08-23 12:00:00 trailing"});

    EXPECT_THROW(AuthenticationData::fromAST(ast, nullptr, false), Exception);
}

TEST(AuthenticationData, EmptyPlaintextPasswordRoundTrips)
{
    AuthenticationData original{AuthenticationType::PLAINTEXT_PASSWORD};
    original.setPassword("", std::nullopt, true);

    EXPECT_TRUE(original.getPassword().empty());
    EXPECT_TRUE(AuthenticationData::Util::digestToString(AuthenticationData::Digest{}).empty());
    EXPECT_TRUE(AuthenticationData::Util::stringToDigest(std::string_view{}).empty());

    const auto restored = AuthenticationData::fromAST(*original.toAST(), nullptr, false);
    EXPECT_EQ(restored, original);
}

TEST(AuthenticationData, MalformedASTIsRejected)
{
    ASTAuthenticationData missing_type;
    EXPECT_THROW(AuthenticationData::fromAST(missing_type, nullptr, false), Exception);

    ASTAuthenticationData missing_password;
    missing_password.contains_password = true;
    EXPECT_THROW(AuthenticationData::fromAST(missing_password, nullptr, false), Exception);

    ASTAuthenticationData missing_hash;
    missing_hash.type = AuthenticationType::SHA256_PASSWORD;
    missing_hash.contains_hash = true;
    EXPECT_THROW(AuthenticationData::fromAST(missing_hash, nullptr, false), Exception);

    ASTAuthenticationData missing_server;
    missing_server.type = AuthenticationType::LDAP;
    EXPECT_THROW(AuthenticationData::fromAST(missing_server, nullptr, false), Exception);
}

TEST(AuthenticationData, SurplusASTArgumentsAreRejected)
{
    auto add_argument = [](ASTAuthenticationData & ast, const String & value)
    {
        ast.children.push_back(make_intrusive<ASTLiteral>(value));
    };

    ASTAuthenticationData password;
    password.type = AuthenticationType::PLAINTEXT_PASSWORD;
    password.contains_password = true;
    add_argument(password, "password");
    add_argument(password, "ignored");
    EXPECT_THROW(AuthenticationData::fromAST(password, nullptr, false), Exception);

    ASTAuthenticationData hash;
    hash.type = AuthenticationType::DOUBLE_SHA1_PASSWORD;
    hash.contains_hash = true;
    add_argument(hash, String(40, '0'));
    add_argument(hash, "ignored");
    EXPECT_THROW(AuthenticationData::fromAST(hash, nullptr, false), Exception);

    ASTAuthenticationData ldap;
    ldap.type = AuthenticationType::LDAP;
    add_argument(ldap, "server");
    add_argument(ldap, "ignored");
    EXPECT_THROW(AuthenticationData::fromAST(ldap, nullptr, false), Exception);

    ASTAuthenticationData http;
    http.type = AuthenticationType::HTTP;
    add_argument(http, "server");
    add_argument(http, "basic");
    add_argument(http, "ignored");
    EXPECT_THROW(AuthenticationData::fromAST(http, nullptr, false), Exception);

    ASTAuthenticationData no_password;
    no_password.type = AuthenticationType::NO_PASSWORD;
    add_argument(no_password, "ignored");
    EXPECT_THROW(AuthenticationData::fromAST(no_password, nullptr, false), Exception);

    ASTAuthenticationData no_password_with_flag;
    no_password_with_flag.type = AuthenticationType::NO_PASSWORD;
    no_password_with_flag.contains_password = true;
    EXPECT_THROW(AuthenticationData::fromAST(no_password_with_flag, nullptr, false), Exception);
}

TEST(AuthenticationData, EmptyExternalAuthenticatorNamesAreRejected)
{
    ASTAuthenticationData ldap;
    ldap.type = AuthenticationType::LDAP;
    ldap.children.push_back(make_intrusive<ASTLiteral>(String{}));
    EXPECT_THROW(AuthenticationData::fromAST(ldap, nullptr, false), Exception);

    ASTAuthenticationData http;
    http.type = AuthenticationType::HTTP;
    http.children.push_back(make_intrusive<ASTLiteral>(String{}));
    EXPECT_THROW(AuthenticationData::fromAST(http, nullptr, false), Exception);
}

TEST(AuthenticationData, ScramPasswordHashMustHaveSHA256Length)
{
    AuthenticationData authentication_data{AuthenticationType::SCRAM_SHA256_PASSWORD};

    EXPECT_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(31), std::nullopt, false), Exception);
    EXPECT_NO_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(32), std::nullopt, false));
    EXPECT_THROW(authentication_data.setPasswordHashBinary(AuthenticationData::Digest(33), std::nullopt, false), Exception);
}

TEST(AuthenticationData, ScramSaltMustUseCanonicalBase64)
{
    AuthenticationData authentication_data{AuthenticationType::SCRAM_SHA256_PASSWORD};

    EXPECT_NO_THROW(authentication_data.setSalt(""));
    EXPECT_NO_THROW(authentication_data.setSalt("YWJj"));
    EXPECT_THROW(authentication_data.setSalt("not@base64"), Exception);
    EXPECT_THROW(authentication_data.setSalt("a"), Exception);
    EXPECT_EQ(authentication_data.getSalt(), "YWJj");
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

#if USE_BCRYPT
TEST(AuthenticationData, BcryptRejectsEmbeddedNullBytes)
{
    const String password = "prefix";
    const String password_with_null{"prefix\0suffix", 13};
    const auto hash = AuthenticationData::Util::encodeBcrypt(password, 4);

    EXPECT_THROW(AuthenticationData::Util::encodeBcrypt(password_with_null, 4), Exception);
    EXPECT_FALSE(AuthenticationData::Util::checkPasswordBcrypt(password_with_null, hash));
    EXPECT_TRUE(AuthenticationData::Util::checkPasswordBcrypt(password, hash));
}

TEST(AuthenticationData, BcryptRejectsPasswordsAboveItsInputLimit)
{
    const String password(72, 'a');
    const auto hash = AuthenticationData::Util::encodeBcrypt(password, 4);

    EXPECT_TRUE(AuthenticationData::Util::checkPasswordBcrypt(password, hash));
    EXPECT_FALSE(AuthenticationData::Util::checkPasswordBcrypt(password + "b", hash));
}
#endif

TEST(Authentication, OneTimePasswordRejectsNonASCIIBytes)
{
    const OneTimePasswordSecret secret{"JBSWY3DPEHPK3PXP"};
    String password(secret.params.num_digits, '1');
    password.front() = static_cast<char>(0xFF);

    EXPECT_FALSE(checkOneTimePassword(password, secret));
}

TEST(Authentication, MySQLCredentialsCannotBypassOneTimePassword)
{
    const String password = "password";
    const String scramble = "01234567890123456789";
    const auto password_sha1 = AuthenticationData::Util::encodeSHA1(password);
    const auto password_double_sha1 = AuthenticationData::Util::encodeSHA1(password_sha1);

    Poco::SHA1Engine engine;
    engine.update(scramble.data(), scramble.size());
    engine.update(password_double_sha1.data(), password_double_sha1.size());
    const auto & challenge_digest = engine.digest();

    String scrambled_password(password_sha1.size(), 0);
    for (size_t i = 0; i != password_sha1.size(); ++i)
        scrambled_password[i] = static_cast<char>(password_sha1[i] ^ challenge_digest[i]);

    AuthenticationData authentication_data{AuthenticationType::PLAINTEXT_PASSWORD};
    authentication_data.setPassword(password, OneTimePasswordSecret{"JBSWY3DPEHPK3PXP"}, true);
    MySQLNative41Credentials credentials{"user", scramble, scrambled_password};
    ExternalAuthenticators external_authenticators;
    ClientInfo client_info;
    SettingsChanges settings;

    EXPECT_EQ(
        Authentication::areCredentialsValid(credentials, authentication_data, external_authenticators, client_info, settings),
        Authentication::CredentialsCheckResult::Fail);
}

#if USE_SSL
TEST(AuthenticationData, EmptySSLCertificateSubjectsAreRejected)
{
    AuthenticationData authentication_data{AuthenticationType::SSL_CERTIFICATE};
    EXPECT_THROW(
        authentication_data.addSSLCertificateSubject(X509Certificate::Subjects::Type::CN, ""),
        Exception);

    X509Certificate::Subjects subjects;
    subjects.insert(X509Certificate::Subjects::Type::SAN, "");
    EXPECT_THROW(authentication_data.setSSLCertificateSubjects(std::move(subjects)), Exception);

    ASTAuthenticationData ast;
    ast.type = AuthenticationType::SSL_CERTIFICATE;
    ast.ssl_cert_subject_type = "CN";
    ast.children.push_back(make_intrusive<ASTLiteral>(String{}));
    EXPECT_THROW(AuthenticationData::fromAST(ast, nullptr, false), Exception);
}

TEST(Authentication, ScramCredentialsRejectOtherAuthenticationTypes)
{
    const std::string auth_message = "auth-message";
    const auto client_key = hmacSHA256({}, "Client Key");
    const auto stored_key = encodeSHA256(client_key);
    const auto client_signature = hmacSHA256(stored_key, auth_message);

    String client_proof(client_key.size(), 0);
    for (size_t i = 0; i != client_key.size(); ++i)
        client_proof[i] = client_key[i] ^ client_signature[i];

    ScramSHA256Credentials credentials{
        "user", base64Encode(client_proof), auth_message, AuthenticationData::Util::SCRAM_SHA256_ITERATIONS};
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

    auto check = [&](String proof, int iterations = AuthenticationData::Util::SCRAM_SHA256_ITERATIONS)
    {
        ScramSHA256Credentials credentials{"user", proof, auth_message, iterations};
        return Authentication::areCredentialsValid(
            credentials, authentication_data, external_authenticators, client_info, settings);
    };

    EXPECT_EQ(check(encoded_proof), Authentication::CredentialsCheckResult::Success);

    authentication_data.setPasswordHashBinary(
        salted_password, OneTimePasswordSecret{"JBSWY3DPEHPK3PXP"}, true);
    EXPECT_EQ(check(encoded_proof), Authentication::CredentialsCheckResult::Fail);
    authentication_data.setPasswordHashBinary(salted_password, std::nullopt, true);

    String wrong_first_byte = encoded_proof;
    wrong_first_byte.front() ^= 1;
    EXPECT_EQ(check(wrong_first_byte), Authentication::CredentialsCheckResult::Fail);

    String wrong_last_byte = encoded_proof;
    wrong_last_byte.back() ^= 1;
    EXPECT_EQ(check(wrong_last_byte), Authentication::CredentialsCheckResult::Fail);

    EXPECT_EQ(check(encoded_proof, 1), Authentication::CredentialsCheckResult::Fail);
}
#endif

#if USE_SSH
TEST(AuthenticationData, EmptySSHKeyListIsRejected)
{
    AuthenticationData authentication_data{AuthenticationType::SSH_KEY};
    EXPECT_THROW(authentication_data.setSSHKeys({}), Exception);
}
#endif
