#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledRowPolicies.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/RowPolicy.h>
#include <Core/UUID.h>


using namespace DB;

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
