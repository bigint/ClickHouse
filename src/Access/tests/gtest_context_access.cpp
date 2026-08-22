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

TEST(ContextAccess, UserChangesResolveCompositeOwner)
{
    AccessControl access_control;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", access_control.getChangesNotifier(), true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", access_control.getChangesNotifier(), true);
    const auto user_id = UUIDHelpers::generateV4();

    auto higher_priority_user = std::make_shared<User>();
    higher_priority_user->setName("higher_priority");
    higher_priority_storage->insert(user_id, higher_priority_user, false, true);

    auto lower_priority_user = std::make_shared<User>();
    lower_priority_user->setName("lower_priority");
    lower_priority_storage->insert(user_id, lower_priority_user, false, true);

    access_control.setStorages({higher_priority_storage, lower_priority_storage});
    Settings settings;
    ClientInfo client_info;
    ContextAccessParams params(user_id, false, true, nullptr, nullptr, settings, "", client_info, {});
    const auto context_access = access_control.getContextAccess(params);
    EXPECT_EQ(context_access->getUserName(), "higher_priority");

    lower_priority_storage->update(
        user_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated = std::static_pointer_cast<User>(entity->clone());
            updated->setName("lower_priority_updated");
            return updated;
        });
    access_control.getChangesNotifier().sendNotifications();
    EXPECT_EQ(context_access->getUserName(), "higher_priority");
}

TEST(ContextAccess, FailedUserRefreshClearsStaleAccess)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto user = std::make_shared<User>();
    user->setName("user");
    user->access.grant(AccessType::SELECT);
    const auto user_id = access_control.insert(user);

    Settings settings;
    ClientInfo client_info;
    ContextAccessParams params(user_id, false, true, nullptr, nullptr, settings, "", client_info, {});
    const auto context_access = access_control.getContextAccess(params);
    EXPECT_TRUE(context_access->getAccessRights()->isGranted(AccessType::SELECT));

    access_control.update(
        user_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_user = std::static_pointer_cast<User>(entity->clone());
            auto & invalid_constraint = updated_user->settings.emplace_back();
            invalid_constraint.setting_name = "max_threads";
            invalid_constraint.min_value = Field{String{"not-a-number"}};
            return updated_user;
        });

    EXPECT_FALSE(context_access->getAccessRights()->isGranted(AccessType::SELECT));
}
