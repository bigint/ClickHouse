#include <Access/RolesOrUsersSet.h>
#include <Core/UUID.h>
#include <gtest/gtest.h>

using namespace DB;

TEST(RolesOrUsersSet, RemoveConsecutiveExceptDependencies)
{
    RolesOrUsersSet set{RolesOrUsersSet::AllTag{}};
    set.except_ids = {UUIDHelpers::generateV4(), UUIDHelpers::generateV4(), UUIDHelpers::generateV4()};
    auto it = set.except_ids.begin();
    const UUID first_id = *it++;
    const UUID second_id = *it++;
    const UUID remaining_id = *it;
    set.removeDependencies({first_id, second_id});

    EXPECT_EQ(set.except_ids, boost::container::flat_set<UUID>{remaining_id});
}
