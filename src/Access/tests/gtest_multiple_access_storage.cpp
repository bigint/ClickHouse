#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/MultipleAccessStorage.h>
#include <Access/Role.h>
#include <Access/User.h>
#include <Core/UUID.h>
#include <Common/Exception.h>

#include <chrono>
#include <future>
#include <stdexcept>


using namespace DB;

namespace DB::ErrorCodes
{
extern const int UNFINISHED;
}

namespace
{

AccessEntityPtr makeUser(const String & name)
{
    auto user = std::make_shared<User>();
    user->setName(name);
    return user;
}

class ThrowingReloadMemoryAccessStorage : public MemoryAccessStorage
{
public:
    ThrowingReloadMemoryAccessStorage(AccessChangesNotifier & notifier_, UUID changed_id_)
        : MemoryAccessStorage("throwing_reload", notifier_, true)
        , notifier(notifier_)
        , changed_id(changed_id_)
    {
    }

    void reload(ReloadMode) override
    {
        notifier.onEntityRemoved(changed_id, AccessEntityType::ROLE);
        throw Exception(ErrorCodes::UNFINISHED, "reload failed");
    }

private:
    AccessChangesNotifier & notifier;
    UUID changed_id;
};

class ThrowingRemoveMemoryAccessStorage : public IAccessStorage
{
public:
    explicit ThrowingRemoveMemoryAccessStorage(AccessChangesNotifier & notifier)
        : IAccessStorage("throwing_remove")
        , memory_storage("throwing_remove_memory", notifier, true)
    {
    }

    UUID insertEntity(const AccessEntityPtr & entity) { return memory_storage.insert(entity); }
    void setThrowID(const UUID & id) { throw_id = id; }

    bool exists(const UUID & id) const override { return memory_storage.exists(id); }

protected:
    std::optional<UUID> findImpl(AccessEntityType type, const String & name) const override { return memory_storage.find(type, name); }
    std::vector<UUID> findAllImpl(AccessEntityType type) const override { return memory_storage.findAll(type); }
    AccessEntityPtr readImpl(const UUID & id, bool throw_if_not_exists) const override
    {
        return memory_storage.read(id, throw_if_not_exists);
    }
    bool insertImpl(
        const UUID & id, const AccessEntityPtr & entity, bool replace_if_exists, bool throw_if_exists, UUID * conflicting_id) override
    {
        return memory_storage.insert(id, entity, replace_if_exists, throw_if_exists, conflicting_id);
    }
    bool removeImpl(const UUID & id, bool throw_if_not_exists) override
    {
        if (id == throw_id)
            throw std::runtime_error("rollback remove failed");
        return memory_storage.remove(id, throw_if_not_exists);
    }
    bool updateImpl(const UUID & id, const UpdateFunc & update_func, bool throw_if_not_exists) override
    {
        return memory_storage.update(id, update_func, throw_if_not_exists);
    }

private:
    MemoryAccessStorage memory_storage;
    UUID throw_id = UUIDHelpers::Nil;
};
}

TEST(MultipleAccessStorage, CollisionCheckUsesEntityReturnedToNestedStorage)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);

    higher_priority_storage->insert(makeUser("reserved_name"));
    const auto lower_priority_id = lower_priority_storage->insert(makeUser("original_name"));

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    size_t update_calls = 0;
    storage.update(
        lower_priority_id,
        [&](const AccessEntityPtr & entity, const UUID &)
        {
            auto updated_user = std::static_pointer_cast<User>(entity->clone());
            updated_user->setName(++update_calls == 1 ? "available_name" : "reserved_name");
            return updated_user;
        });

    EXPECT_EQ(update_calls, 1u);
    EXPECT_EQ(lower_priority_storage->read<User>(lower_priority_id)->getName(), "available_name");
}

TEST(MultipleAccessStorage, RenameRejectsCollisionInLaterStorage)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);

    const auto higher_priority_id = higher_priority_storage->insert(makeUser("original_name"));
    lower_priority_storage->insert(makeUser("reserved_name"));

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    EXPECT_THROW(
        storage.update(
            higher_priority_id,
            [](const AccessEntityPtr & entity, const UUID &)
            {
                auto updated_user = std::static_pointer_cast<User>(entity->clone());
                updated_user->setName("reserved_name");
                return updated_user;
            }),
        Exception);
    EXPECT_EQ(higher_priority_storage->read<User>(higher_priority_id)->getName(), "original_name");
}

TEST(MultipleAccessStorage, MutationsAreSerializedAcrossNestedStorages)
{
    AccessChangesNotifier notifier;
    auto first_storage = std::make_shared<MemoryAccessStorage>("first", notifier, true);
    auto second_storage = std::make_shared<MemoryAccessStorage>("second", notifier, true);
    const auto first_id = first_storage->insert(makeUser("first_user"));
    const auto second_id = second_storage->insert(makeUser("second_user"));

    MultipleAccessStorage storage;
    storage.setStorages({first_storage, second_storage});

    std::promise<void> first_callback_entered_promise;
    auto first_callback_entered = first_callback_entered_promise.get_future();
    std::promise<void> release_first_callback_promise;
    auto release_first_callback = release_first_callback_promise.get_future();
    auto first_update = std::async(
        std::launch::async,
        [&]
        {
            storage.update(
                first_id,
                [&](const AccessEntityPtr & entity, const UUID &)
                {
                    first_callback_entered_promise.set_value();
                    release_first_callback.wait();
                    return entity;
                });
        });
    first_callback_entered.wait();

    std::promise<void> second_update_started_promise;
    auto second_update_started = second_update_started_promise.get_future();
    std::promise<void> second_callback_entered_promise;
    auto second_callback_entered = second_callback_entered_promise.get_future();
    auto second_update = std::async(
        std::launch::async,
        [&]
        {
            second_update_started_promise.set_value();
            storage.update(
                second_id,
                [&](const AccessEntityPtr & entity, const UUID &)
                {
                    second_callback_entered_promise.set_value();
                    return entity;
                });
        });
    second_update_started.wait();

    EXPECT_EQ(second_callback_entered.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout);
    release_first_callback_promise.set_value();
    first_update.get();
    second_update.get();
    EXPECT_EQ(second_callback_entered.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
}

TEST(MultipleAccessStorage, RemoveIsSerializedWithOtherMutations)
{
    AccessChangesNotifier notifier;
    auto first_storage = std::make_shared<MemoryAccessStorage>("first", notifier, true);
    auto second_storage = std::make_shared<MemoryAccessStorage>("second", notifier, true);
    const auto first_id = first_storage->insert(makeUser("first_user"));
    const auto second_id = second_storage->insert(makeUser("second_user"));

    MultipleAccessStorage storage;
    storage.setStorages({first_storage, second_storage});

    std::promise<void> update_entered_promise;
    auto update_entered = update_entered_promise.get_future();
    std::promise<void> release_update_promise;
    auto release_update = release_update_promise.get_future();
    auto update = std::async(
        std::launch::async,
        [&]
        {
            storage.update(
                first_id,
                [&](const AccessEntityPtr & entity, const UUID &)
                {
                    update_entered_promise.set_value();
                    release_update.wait();
                    return entity;
                });
        });
    update_entered.wait();

    auto removal = std::async(std::launch::async, [&] { storage.remove(second_id); });
    EXPECT_EQ(removal.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout);

    release_update_promise.set_value();
    update.get();
    removal.get();
    EXPECT_FALSE(second_storage->exists(second_id));
}

TEST(MultipleAccessStorage, StorageTopologyChangesAreSerializedWithMutations)
{
    AccessChangesNotifier notifier;
    auto first_storage = std::make_shared<MemoryAccessStorage>("first", notifier, true);
    auto second_storage = std::make_shared<MemoryAccessStorage>("second", notifier, true);
    const auto id = first_storage->insert(makeUser("user"));

    MultipleAccessStorage storage;
    storage.setStorages({first_storage, second_storage});

    std::promise<void> update_entered_promise;
    auto update_entered = update_entered_promise.get_future();
    std::promise<void> release_update_promise;
    auto release_update = release_update_promise.get_future();
    auto update = std::async(
        std::launch::async,
        [&]
        {
            storage.update(
                id,
                [&](const AccessEntityPtr & entity, const UUID &)
                {
                    update_entered_promise.set_value();
                    release_update.wait();
                    return entity;
                });
        });
    update_entered.wait();

    auto topology_change = std::async(std::launch::async, [&] { storage.setStorages({first_storage}); });
    EXPECT_EQ(topology_change.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout);

    release_update_promise.set_value();
    update.get();
    topology_change.get();
    const auto storages = storage.getStorages();
    ASSERT_EQ(storages.size(), 1u);
    EXPECT_EQ(storages.front(), first_storage);
}

TEST(MultipleAccessStorage, InsertFindsNameCollisionInLaterStorage)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);

    const auto existing_id = lower_priority_storage->insert(makeUser("existing_user"));

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    UUID conflicting_id;
    EXPECT_FALSE(storage.insert(UUIDHelpers::generateV4(), makeUser("existing_user"), false, false, &conflicting_id));
    EXPECT_EQ(conflicting_id, existing_id);
    EXPECT_TRUE(higher_priority_storage->findAll<User>().empty());
}

TEST(MultipleAccessStorage, ReplaceFindsIDCollisionInLaterStorage)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);

    const auto existing_id = lower_priority_storage->insert(makeUser("old_name"));

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    EXPECT_TRUE(storage.insert(existing_id, makeUser("new_name"), true, false));
    EXPECT_TRUE(higher_priority_storage->findAll<User>().empty());
    EXPECT_EQ(lower_priority_storage->read<User>(existing_id)->getName(), "new_name");
}

TEST(MultipleAccessStorage, ReplaceRejectsCollisionsInDifferentStorages)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);

    const auto conflicting_name_id = higher_priority_storage->insert(makeUser("new_name"));
    const auto conflicting_id = lower_priority_storage->insert(makeUser("old_name"));

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    EXPECT_THROW(storage.insert(conflicting_id, makeUser("new_name"), true, false), Exception);
    EXPECT_EQ(higher_priority_storage->read<User>(conflicting_name_id)->getName(), "new_name");
    EXPECT_EQ(lower_priority_storage->read<User>(conflicting_id)->getName(), "old_name");
}

TEST(MultipleAccessStorage, CachedStorageDoesNotOverrideHigherPriorityStorage)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);
    const auto id = UUIDHelpers::generateV4();
    lower_priority_storage->insert(id, makeUser("lower_priority_user"), false, true);

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});
    EXPECT_EQ(storage.read<User>(id)->getName(), "lower_priority_user");

    higher_priority_storage->insert(id, makeUser("higher_priority_user"), false, true);
    EXPECT_EQ(storage.read<User>(id)->getName(), "higher_priority_user");
    EXPECT_EQ(storage.getStorage(id), higher_priority_storage);
}

TEST(MultipleAccessStorage, FindAllOmitsIDsShadowedByAnotherEntityType)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);
    const auto id = UUIDHelpers::generateV4();

    auto role = std::make_shared<Role>();
    role->setName("higher_priority_role");
    higher_priority_storage->insert(id, role, false, true);
    lower_priority_storage->insert(id, makeUser("lower_priority_user"), false, true);

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    EXPECT_EQ(storage.findAll<Role>(), std::vector<UUID>{id});
    EXPECT_TRUE(storage.findAll<User>().empty());
}

TEST(MultipleAccessStorage, FindAllDeduplicatesVisibleEntityIDs)
{
    AccessChangesNotifier notifier;
    auto higher_priority_storage = std::make_shared<MemoryAccessStorage>("higher_priority", notifier, true);
    auto lower_priority_storage = std::make_shared<MemoryAccessStorage>("lower_priority", notifier, true);
    const auto id = UUIDHelpers::generateV4();

    higher_priority_storage->insert(id, makeUser("higher_priority_user"), false, true);
    lower_priority_storage->insert(id, makeUser("lower_priority_user"), false, true);

    MultipleAccessStorage storage;
    storage.setStorages({higher_priority_storage, lower_priority_storage});

    EXPECT_EQ(storage.findAll<User>(), std::vector<UUID>{id});
}

TEST(MultipleAccessStorage, MovePreservesReferencesToMovedEntity)
{
    AccessChangesNotifier notifier;
    auto source_storage = std::make_shared<MemoryAccessStorage>("source", notifier, true);
    auto destination_storage = std::make_shared<MemoryAccessStorage>("destination", notifier, true);

    auto role = std::make_shared<Role>();
    role->setName("moved_role");
    const auto role_id = source_storage->insert(role);

    auto user = std::make_shared<User>();
    user->setName("dependent_user");
    user->granted_roles.grant(role_id);
    const auto user_id = source_storage->insert(user);

    MultipleAccessStorage storage;
    storage.setStorages({source_storage, destination_storage});
    storage.moveAccessEntities({role_id}, source_storage->getStorageName(), destination_storage->getStorageName());

    EXPECT_FALSE(source_storage->exists(role_id));
    EXPECT_TRUE(destination_storage->exists(role_id));
    EXPECT_TRUE(source_storage->read<User>(user_id)->granted_roles.isGranted(role_id));
}

TEST(MultipleAccessStorage, MoveRollsBackPartialDestinationInsertion)
{
    AccessChangesNotifier notifier;
    auto source_storage = std::make_shared<MemoryAccessStorage>("source", notifier, true);
    auto destination_storage = std::make_shared<MemoryAccessStorage>("destination", notifier, true);

    auto first_role = std::make_shared<Role>();
    first_role->setName("first_role");
    const auto first_role_id = source_storage->insert(first_role);

    auto conflicting_role = std::make_shared<Role>();
    conflicting_role->setName("conflicting_role");
    const auto conflicting_role_id = source_storage->insert(conflicting_role);
    const auto destination_role_id = destination_storage->insert(conflicting_role);

    MultipleAccessStorage storage;
    storage.setStorages({source_storage, destination_storage});

    EXPECT_THROW(
        storage.moveAccessEntities(
            {first_role_id, conflicting_role_id}, source_storage->getStorageName(), destination_storage->getStorageName()),
        Exception);

    EXPECT_TRUE(source_storage->exists(first_role_id));
    EXPECT_TRUE(source_storage->exists(conflicting_role_id));
    EXPECT_FALSE(destination_storage->exists(first_role_id));
    EXPECT_EQ(destination_storage->getID<Role>("conflicting_role"), destination_role_id);
}

TEST(MultipleAccessStorage, MoveRestoresSourceAfterDestinationRollbackFailure)
{
    AccessChangesNotifier notifier;
    auto source_storage = std::make_shared<MemoryAccessStorage>("source", notifier, true);
    auto destination_storage = std::make_shared<ThrowingRemoveMemoryAccessStorage>(notifier);

    auto first_role = std::make_shared<Role>();
    first_role->setName("first_role");
    const auto first_role_id = source_storage->insert(first_role);

    auto conflicting_role = std::make_shared<Role>();
    conflicting_role->setName("conflicting_role");
    const auto conflicting_role_id = source_storage->insert(conflicting_role);
    destination_storage->insertEntity(conflicting_role);
    destination_storage->setThrowID(first_role_id);

    MultipleAccessStorage storage;
    storage.setStorages({source_storage, destination_storage});

    EXPECT_THROW(
        storage.moveAccessEntities(
            {first_role_id, conflicting_role_id}, source_storage->getStorageName(), destination_storage->getStorageName()),
        Exception);

    EXPECT_TRUE(source_storage->exists(first_role_id));
    EXPECT_TRUE(source_storage->exists(conflicting_role_id));
}

TEST(AccessControl, MoveDeliversNestedStorageNotifications)
{
    AccessControl access_control;
    auto source_storage = std::make_shared<MemoryAccessStorage>("source", access_control.getChangesNotifier(), true);
    auto destination_storage = std::make_shared<MemoryAccessStorage>("destination", access_control.getChangesNotifier(), true);
    access_control.setStorages({source_storage, destination_storage});

    auto role = std::make_shared<Role>();
    role->setName("moved_role");
    const auto role_id = source_storage->insert(role);
    access_control.getChangesNotifier().sendNotifications();

    size_t handler_calls = 0;
    size_t delivered_changes = 0;
    auto subscription = access_control.subscribeForChanges<Role>(
        [&](const std::vector<AccessChangesNotifier::Change> & changes)
        {
            ++handler_calls;
            delivered_changes += changes.size();
        });

    access_control.moveAccessEntities({role_id}, source_storage->getStorageName(), destination_storage->getStorageName());

    EXPECT_EQ(handler_calls, 1u);
    EXPECT_EQ(delivered_changes, 2u);
}

TEST(AccessControl, RemovalNotificationsObserveCleanedDependencies)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto role = std::make_shared<Role>();
    role->setName("role");
    const auto role_id = access_control.insert(role);

    auto user = std::make_shared<User>();
    user->setName("user");
    user->granted_roles.grant(role_id);
    const auto user_id = access_control.insert(user);

    bool dependency_was_cleaned = false;
    auto subscription = access_control.subscribeForChanges<Role>(
        [&](const std::vector<AccessChangesNotifier::Change> & changes)
        {
            if (!changes.empty())
                dependency_was_cleaned = !access_control.read<User>(user_id)->granted_roles.isGranted(role_id);
        });

    access_control.remove(role_id);

    EXPECT_TRUE(dependency_was_cleaned);
}

TEST(AccessControl, ReloadFailureDeliversQueuedNotifications)
{
    AccessControl access_control;
    const auto changed_id = UUIDHelpers::generateV4();
    access_control.setStorages({std::make_shared<ThrowingReloadMemoryAccessStorage>(access_control.getChangesNotifier(), changed_id)});

    size_t delivered_changes = 0;
    auto subscription = access_control.subscribeForChanges<Role>([&](const std::vector<AccessChangesNotifier::Change> & changes)
                                                                 { delivered_changes += changes.size(); });

    EXPECT_THROW(access_control.reload(IAccessStorage::ReloadMode::ALL), Exception);
    EXPECT_EQ(delivered_changes, 1u);
}
