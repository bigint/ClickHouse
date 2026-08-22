#include <gtest/gtest.h>

#include <Access/AccessControl.h>
#include <Access/EnabledRoles.h>
#include <Access/EnabledRolesInfo.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/Role.h>

#include <future>


using namespace DB;

TEST(EnabledRoles, UnsubscribeCancelsQueuedCallback)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto role = std::make_shared<Role>();
    role->setName("role");
    const auto role_id = access_control.insert(role);
    const auto enabled_roles = access_control.getEnabledRoles({role_id}, {});

    std::promise<void> blocker_started_promise;
    auto blocker_started = blocker_started_promise.get_future();
    std::promise<void> release_blocker_promise;
    auto release_blocker = release_blocker_promise.get_future();
    auto blocker = enabled_roles->subscribeForChanges(
        [&](const std::shared_ptr<const EnabledRolesInfo> &)
        {
            blocker_started_promise.set_value();
            release_blocker.wait();
        });

    size_t cancelled_handler_calls = 0;
    auto cancelled = enabled_roles->subscribeForChanges(
        [&](const std::shared_ptr<const EnabledRolesInfo> &) { ++cancelled_handler_calls; });

    auto updater = std::async(
        std::launch::async,
        [&]
        {
            access_control.update(
                role_id,
                [](const AccessEntityPtr & entity, const UUID &)
                {
                    auto updated_role = std::static_pointer_cast<Role>(entity->clone());
                    updated_role->setName("renamed_role");
                    return updated_role;
                });
        });

    blocker_started.wait();
    cancelled.reset();
    release_blocker_promise.set_value();
    updater.get();

    EXPECT_EQ(0u, cancelled_handler_calls);
}

TEST(EnabledRoles, RoleChangesResolveCompositeOwner)
{
    AccessControl access_control;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", access_control.getChangesNotifier(), true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", access_control.getChangesNotifier(), true);
    const auto role_id = UUIDHelpers::generateV4();

    auto higher_priority_role = std::make_shared<Role>();
    higher_priority_role->setName("higher_priority");
    higher_priority_storage->insert(role_id, higher_priority_role, false, true);

    auto lower_priority_role = std::make_shared<Role>();
    lower_priority_role->setName("lower_priority");
    lower_priority_storage->insert(role_id, lower_priority_role, false, true);

    access_control.setStorages({higher_priority_storage, lower_priority_storage});
    const auto enabled_roles = access_control.getEnabledRoles({role_id}, {});
    EXPECT_EQ(enabled_roles->getRolesInfo()->names_of_roles.at(role_id), "higher_priority");

    lower_priority_storage->update(
        role_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated = std::static_pointer_cast<Role>(entity->clone());
            updated->setName("lower_priority_updated");
            return updated;
        });
    access_control.getChangesNotifier().sendNotifications();
    EXPECT_EQ(enabled_roles->getRolesInfo()->names_of_roles.at(role_id), "higher_priority");
}
