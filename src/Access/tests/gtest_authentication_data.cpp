#include <Access/AuthenticationData.h>
#include <Access/Common/OneTimePassword.h>
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
