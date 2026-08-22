#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledRowPolicies.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/RowPolicy.h>
#include <Core/UUID.h>


using namespace DB;

TEST(EnabledRowPolicies, DefaultConstructionHasEmptyFilters)
{
    EnabledRowPolicies enabled_policies;

    EXPECT_FALSE(enabled_policies.getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER));
}

TEST(RowPolicyCache, InvalidRestrictiveFilterFailsClosed)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto policy = std::make_shared<RowPolicy>();
    policy->setFullName("policy", "database", "table");
    policy->setRestrictive();
    policy->to_roles = RolesOrUsersSet::AllTag{};
    policy->filters[static_cast<size_t>(RowPolicyFilterType::SELECT_FILTER)] = "(";
    access_control.insert(policy);

    auto enabled_policies = access_control.getEnabledRowPolicies(UUIDHelpers::generateV4(), {});
    auto filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);

    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysFalse());
}

TEST(RowPolicyCache, UsersWithoutPoliciesSettingRefreshesExistingEnabledPolicies)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto policy = std::make_shared<RowPolicy>();
    policy->setFullName("policy", "database", "table");
    policy->to_roles = RolesOrUsersSet(UUIDHelpers::generateV4());
    policy->filters[static_cast<size_t>(RowPolicyFilterType::SELECT_FILTER)] = "1";
    access_control.insert(policy);

    auto enabled_policies = access_control.getEnabledRowPolicies(UUIDHelpers::generateV4(), {});
    auto filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);
    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysFalse());

    access_control.setEnabledUsersWithoutRowPoliciesCanReadRows(true);
    filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);
    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysTrue());

    access_control.setEnabledUsersWithoutRowPoliciesCanReadRows(false);
    filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);
    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysFalse());
}

TEST(RowPolicyCache, PolicyChangesResolveCompositeOwner)
{
    AccessControl access_control;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", access_control.getChangesNotifier(), true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", access_control.getChangesNotifier(), true);
    const auto policy_id = UUIDHelpers::generateV4();

    auto higher_priority_policy = std::make_shared<RowPolicy>();
    higher_priority_policy->setFullName("higher_priority", "database", "table");
    higher_priority_policy->to_roles = RolesOrUsersSet::AllTag{};
    higher_priority_policy->filters[static_cast<size_t>(RowPolicyFilterType::SELECT_FILTER)] = "1";
    higher_priority_storage->insert(policy_id, higher_priority_policy, false, true);

    auto lower_priority_policy = std::make_shared<RowPolicy>();
    lower_priority_policy->setFullName("lower_priority", "database", "table");
    lower_priority_policy->to_roles = RolesOrUsersSet::AllTag{};
    lower_priority_policy->filters[static_cast<size_t>(RowPolicyFilterType::SELECT_FILTER)] = "0";
    lower_priority_storage->insert(policy_id, lower_priority_policy, false, true);

    access_control.setStorages({higher_priority_storage, lower_priority_storage});
    auto enabled_policies = access_control.getEnabledRowPolicies(UUIDHelpers::generateV4(), {});
    auto filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);
    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysTrue());

    lower_priority_storage->update(
        policy_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated = std::static_pointer_cast<RowPolicy>(entity->clone());
            updated->setShortName("lower_priority_updated");
            return updated;
        });
    access_control.getChangesNotifier().sendNotifications();
    filter = enabled_policies->getFilter("database", "table", RowPolicyFilterType::SELECT_FILTER);
    ASSERT_TRUE(filter);
    EXPECT_TRUE(filter->isAlwaysTrue());
}
