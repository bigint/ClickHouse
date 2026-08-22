#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledQuota.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/Quota.h>
#include <Access/QuotaUsage.h>
#include <Core/UUID.h>
#include <Common/Exception.h>


using namespace DB;

TEST(QuotaCache, NormalizedHashResolverOutlivesAccessControl)
{
    std::shared_ptr<const EnabledQuota> enabled_quota;
    {
        AccessControl access_control;
        auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
        access_control.setStorages({storage});

        auto quota = std::make_shared<Quota>();
        quota->setName("normalized_hash_quota");
        quota->key_type = QuotaKeyType::NORMALIZED_QUERY_HASH;
        quota->to_roles = RolesOrUsersSet::AllTag{};
        auto & limits = quota->all_limits.emplace_back();
        limits.duration = std::chrono::minutes(1);
        limits.max[static_cast<size_t>(QuotaType::QUERIES)] = 1;
        access_control.insert(quota);

        enabled_quota = access_control.getEnabledQuota(
            UUIDHelpers::generateV4(), "user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");
    }

    enabled_quota->usedForQuery(42, QuotaType::QUERIES, 1);
    EXPECT_THROW(enabled_quota->usedForQuery(42, QuotaType::QUERIES, 1), Exception);
}

TEST(QuotaCache, PreservesPerNormalizedHashUsageOnUpdate)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto quota = std::make_shared<Quota>();
    quota->setName("normalized_hash_quota");
    quota->key_type = QuotaKeyType::NORMALIZED_QUERY_HASH;
    quota->to_roles = RolesOrUsersSet::AllTag{};
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES_PER_NORMALIZED_HASH)] = 1;
    const auto quota_id = access_control.insert(quota);

    auto enabled_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");
    enabled_quota->usedPerNormalizedHash(42);

    access_control.update(
        quota_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_quota = std::static_pointer_cast<Quota>(entity->clone());
            updated_quota->setName("renamed_normalized_hash_quota");
            return updated_quota;
        });

    EXPECT_THROW(enabled_quota->usedPerNormalizedHash(42), Exception);
}

TEST(QuotaCache, NormalizedHashKeySharesPerHashLimitAcrossUsers)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto quota = std::make_shared<Quota>();
    quota->setName("normalized_hash_quota");
    quota->key_type = QuotaKeyType::NORMALIZED_QUERY_HASH;
    quota->to_roles = RolesOrUsersSet::AllTag{};
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES_PER_NORMALIZED_HASH)] = 1;
    access_control.insert(quota);

    auto first_user_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "first_user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");
    auto second_user_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "second_user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");

    first_user_quota->usedPerNormalizedHash(42);
    EXPECT_THROW(second_user_quota->usedPerNormalizedHash(42), Exception);
}

TEST(QuotaCache, ExceededNormalizedHashDoesNotRejectOtherHashes)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto quota = std::make_shared<Quota>();
    quota->setName("per_hash_quota");
    quota->key_type = QuotaKeyType::USER_NAME;
    quota->to_roles = RolesOrUsersSet::AllTag{};
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES_PER_NORMALIZED_HASH)] = 1;
    access_control.insert(quota);

    auto enabled_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");

    enabled_quota->usedPerNormalizedHash(42);
    EXPECT_THROW(enabled_quota->usedPerNormalizedHash(42), Exception);
    EXPECT_NO_THROW(enabled_quota->usedPerNormalizedHash(43));
}

TEST(QuotaCache, RejectedQueryIsAccountedToEveryMatchingQuota)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    for (const auto & name : {"first", "second"})
    {
        auto quota = std::make_shared<Quota>();
        quota->setName(name);
        quota->key_type = QuotaKeyType::USER_NAME;
        quota->to_roles = RolesOrUsersSet::AllTag{};
        auto & limits = quota->all_limits.emplace_back();
        limits.duration = std::chrono::minutes(1);
        limits.max[static_cast<size_t>(QuotaType::QUERIES)] = 1;
        limits.max[static_cast<size_t>(QuotaType::ERRORS)] = 1;
        access_control.insert(quota);
    }

    auto enabled_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");
    enabled_quota->usedForQuery(42, {{QuotaType::QUERIES, 1}, {QuotaType::ERRORS, 1}});
    EXPECT_THROW(enabled_quota->usedForQuery(42, {{QuotaType::QUERIES, 1}, {QuotaType::ERRORS, 1}}), Exception);

    const auto usages = enabled_quota->getAllUsage();
    ASSERT_EQ(2u, usages.size());
    for (const auto & usage : usages)
    {
        ASSERT_EQ(1u, usage.intervals.size());
        EXPECT_EQ(2u, usage.intervals.front().used[static_cast<size_t>(QuotaType::QUERIES)]);
        EXPECT_EQ(2u, usage.intervals.front().used[static_cast<size_t>(QuotaType::ERRORS)]);
    }
}

TEST(QuotaCache, KeyTypeChangeDropsOldUsageBuckets)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto quota = std::make_shared<Quota>();
    quota->setName("quota");
    quota->key_type = QuotaKeyType::USER_NAME;
    quota->to_roles = RolesOrUsersSet::AllTag{};
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES)] = 100;
    const auto quota_id = access_control.insert(quota);

    auto enabled_quota = access_control.getEnabledQuota(
        UUIDHelpers::generateV4(), "user", {}, std::make_shared<Poco::Net::IPAddress>("127.0.0.1"), "", "");
    enabled_quota->used(QuotaType::QUERIES, 1);
    const auto initial_usages = access_control.getAllQuotasUsage();
    ASSERT_EQ(1u, initial_usages.size());
    EXPECT_EQ("user", initial_usages.front().quota_key);

    access_control.update(
        quota_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_quota = std::static_pointer_cast<Quota>(entity->clone());
            updated_quota->key_type = QuotaKeyType::IP_ADDRESS;
            return updated_quota;
        });

    const auto usages = access_control.getAllQuotasUsage();
    ASSERT_EQ(1u, usages.size());
    EXPECT_EQ("127.0.0.1", usages.front().quota_key);
    ASSERT_EQ(1u, usages.front().intervals.size());
    EXPECT_EQ(0u, usages.front().intervals.front().used[static_cast<size_t>(QuotaType::QUERIES)]);
}

TEST(QuotaCache, ForwardedPrefixRejectsMalformedAddress)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto quota = std::make_shared<Quota>();
    quota->setName("forwarded_ip_quota");
    quota->key_type = QuotaKeyType::FORWARDED_IP_ADDRESS;
    quota->ipv4_prefix_bits = 24;
    quota->to_roles = RolesOrUsersSet::AllTag{};
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES)] = 1;
    access_control.insert(quota);

    EXPECT_THROW(
        access_control.getEnabledQuota(
            UUIDHelpers::generateV4(),
            "user",
            {},
            std::make_shared<Poco::Net::IPAddress>("127.0.0.1"),
            "not-an-ip",
            ""),
        Exception);
}
