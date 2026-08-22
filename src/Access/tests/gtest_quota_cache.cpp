#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledQuota.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/Quota.h>
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
