#include <gtest/gtest.h>

#include <Access/AccessControl.h>
#include <Access/ContextAccess.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/Quota.h>
#include <Access/Role.h>
#include <Access/User.h>
#include <Core/Settings.h>
#include <Interpreters/ClientInfo.h>


using namespace DB;

TEST(ContextAccess, RoleChangesRefreshQuotaAssignment)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto assigned_role = std::make_shared<Role>();
    assigned_role->setName("assigned_role");
    const auto assigned_role_id = access_control.insert(assigned_role);

    auto current_role = std::make_shared<Role>();
    current_role->setName("current_role");
    const auto current_role_id = access_control.insert(current_role);

    auto user = std::make_shared<User>();
    user->setName("user");
    user->granted_roles.grant(current_role_id);
    const auto user_id = access_control.insert(user);

    auto quota = std::make_shared<Quota>();
    quota->setName("role_quota");
    quota->key_type = QuotaKeyType::USER_NAME;
    quota->to_roles = RolesOrUsersSet(assigned_role_id);
    auto & limits = quota->all_limits.emplace_back();
    limits.duration = std::chrono::minutes(1);
    limits.max[static_cast<size_t>(QuotaType::QUERIES)] = 100;
    access_control.insert(quota);

    Settings settings;
    ClientInfo client_info;
    ContextAccessParams params(user_id, false, true, nullptr, nullptr, settings, "", client_info, {});
    const auto context_access = access_control.getContextAccess(params);
    EXPECT_TRUE(context_access->getQuotaUsages().empty());

    access_control.update(
        current_role_id,
        [assigned_role_id](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_role = std::static_pointer_cast<Role>(entity->clone());
            updated_role->granted_roles.grant(assigned_role_id);
            return updated_role;
        });
    ASSERT_EQ(1u, context_access->getQuotaUsages().size());
    EXPECT_EQ("role_quota", context_access->getQuotaUsages().front().quota_name);

    access_control.update(
        current_role_id,
        [assigned_role_id](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_role = std::static_pointer_cast<Role>(entity->clone());
            updated_role->granted_roles.revoke(assigned_role_id);
            return updated_role;
        });
    EXPECT_TRUE(context_access->getQuotaUsages().empty());
}
