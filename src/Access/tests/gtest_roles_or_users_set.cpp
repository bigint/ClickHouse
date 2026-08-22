#include <Access/RolesOrUsersSet.h>
#include <Common/Exception.h>
#include <Core/UUID.h>
#include <Parsers/Access/ASTRolesOrUsersSet.h>
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

TEST(RolesOrUsersSet, CurrentUserRequiresID)
{
    ASTRolesOrUsersSet ast;
    ast.current_user = true;
    ast.allow_users = true;

    EXPECT_THROW(RolesOrUsersSet{ast}, Exception);

    ast.current_user = false;
    ast.all = true;
    ast.except_current_user = true;
    EXPECT_THROW(RolesOrUsersSet{ast}, Exception);
}

TEST(RolesOrUsersSet, NamedEntitiesRequireAccessControl)
{
    ASTRolesOrUsersSet ast;
    ast.names = {"role"};
    ast.allow_roles = true;

    EXPECT_THROW(RolesOrUsersSet{ast}, Exception);
}
