#include <Access/GrantedRoles.h>
#include <Core/UUID.h>
#include <gtest/gtest.h>

using namespace DB;

TEST(GrantedRoles, CopyDependenciesReplacesAdminOption)
{
    const UUID role_id = UUIDHelpers::generateV4();

    GrantedRoles without_admin_option;
    without_admin_option.grant(role_id);

    GrantedRoles with_admin_option;
    with_admin_option.grantWithAdminOption(role_id);

    auto destination = with_admin_option;
    destination.copyDependenciesFrom(without_admin_option, {role_id});
    EXPECT_TRUE(destination.isGranted(role_id));
    EXPECT_FALSE(destination.isGrantedWithAdminOption(role_id));

    destination = without_admin_option;
    destination.copyDependenciesFrom(with_admin_option, {role_id});
    EXPECT_TRUE(destination.isGrantedWithAdminOption(role_id));

    GrantedRoles absent;
    destination.copyDependenciesFrom(absent, {role_id});
    EXPECT_FALSE(destination.isGranted(role_id));
    EXPECT_FALSE(destination.isGrantedWithAdminOption(role_id));
}
