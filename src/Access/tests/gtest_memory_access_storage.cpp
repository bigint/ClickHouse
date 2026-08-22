#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/Role.h>
#include <Access/User.h>
#include <Core/UUID.h>
#include <IO/WriteHelpers.h>
#include <Common/Logger.h>

#include <Poco/AutoPtr.h>
#include <Poco/StreamChannel.h>

#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>


using namespace DB;

namespace
{

class MemoryAccessStorageTestAdapter : public MemoryAccessStorage
{
public:
    using MemoryAccessStorage::clearConflictsInEntitiesList;
};

class ThrowingRemoveAccessStorage : public IAccessStorage
{
public:
    explicit ThrowingRemoveAccessStorage(AccessChangesNotifier & notifier)
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
    bool removeImpl(const UUID & id, bool throw_if_not_exists) override
    {
        if (id == throw_id)
            throw std::runtime_error("remove failed");
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

template <typename Entity>
AccessEntityPtr makeEntity(const String & name)
{
    auto entity = std::make_shared<Entity>();
    entity->setName(name);
    return entity;
}

using EntityWithID = std::pair<UUID, AccessEntityPtr>;

String makeConflictWarning(const EntityWithID & entity)
{
    return "Skipping " + entity.second->formatTypeWithName() + " (id=" + toString(entity.first)
        + ") due to conflicts with other access entities\n";
}

}

TEST(MemoryAccessStorage, ConflictCleanupKeepsNonConflictingEntities)
{
    std::vector<EntityWithID> entities{
        {UUIDHelpers::generateV4(), makeEntity<User>("shared_name")},
        {UUIDHelpers::generateV4(), makeEntity<Role>("shared_name")},
        {UUIDHelpers::generateV4(), makeEntity<User>("other_name")},
    };
    const auto expected_entities = entities;

    MemoryAccessStorageTestAdapter::clearConflictsInEntitiesList(entities, getLogger("MemoryAccessStorageNoConflictsTest"));

    EXPECT_EQ(entities, expected_entities);
}

TEST(MemoryAccessStorage, ConflictCleanupRemovesOverlappingConflictsOnce)
{
    const auto shared_id = UUIDHelpers::generateV4();
    std::vector<EntityWithID> entities{
        {UUIDHelpers::generateV4(), makeEntity<User>("first")},
        {shared_id, makeEntity<User>("alpha")},
        {shared_id, makeEntity<User>("beta")},
        {shared_id, makeEntity<User>("gamma")},
        {UUIDHelpers::generateV4(), makeEntity<User>("gamma")},
        {UUIDHelpers::generateV4(), makeEntity<Role>("gamma")},
        {UUIDHelpers::generateV4(), makeEntity<Role>("duplicate_role")},
        {UUIDHelpers::generateV4(), makeEntity<Role>("duplicate_role")},
        {UUIDHelpers::generateV4(), makeEntity<User>("last")},
    };

    const std::vector<EntityWithID> expected_entities{entities[0], entities[5], entities[8]};
    const String expected_warnings = makeConflictWarning(entities[1]) + makeConflictWarning(entities[2]) + makeConflictWarning(entities[3])
        + makeConflictWarning(entities[4]) + makeConflictWarning(entities[6]) + makeConflictWarning(entities[7]);

    std::ostringstream warnings; // STYLE_CHECK_ALLOW_STD_STRING_STREAM
    auto channel = Poco::AutoPtr<Poco::StreamChannel>(new Poco::StreamChannel(warnings));
    auto log = createLogger("MemoryAccessStorageOverlappingConflictsTest", channel.get());

    MemoryAccessStorageTestAdapter::clearConflictsInEntitiesList(entities, log);

    EXPECT_EQ(entities, expected_entities);
    EXPECT_EQ(warnings.str(), expected_warnings);
}

TEST(MemoryAccessStorage, SetAllWithoutNotificationsSuppressesRemovals)
{
    AccessChangesNotifier notifier;
    MemoryAccessStorage storage("memory", notifier, true);
    storage.insert(makeEntity<User>("user"));
    notifier.sendNotifications();

    size_t delivered_changes = 0;
    auto subscription = notifier.subscribeForChanges<User>([&](const std::vector<AccessChangesNotifier::Change> & changes)
                                                           { delivered_changes += changes.size(); });

    storage.setAll({}, /* notify= */ false);
    notifier.sendNotifications();

    EXPECT_EQ(delivered_changes, 0u);
}

TEST(IAccessStorage, BatchRemovalCleansDependenciesAfterStandardException)
{
    AccessChangesNotifier notifier;
    ThrowingRemoveAccessStorage storage(notifier);

    const auto removed_role_id = storage.insertEntity(makeEntity<Role>("removed_role"));
    const auto retained_role_id = storage.insertEntity(makeEntity<Role>("retained_role"));
    storage.setThrowID(retained_role_id);

    auto user = std::make_shared<User>();
    user->setName("user");
    user->granted_roles.grant(removed_role_id);
    const auto user_id = storage.insertEntity(user);

    EXPECT_THROW(storage.remove({removed_role_id, retained_role_id}), std::runtime_error);
    EXPECT_FALSE(storage.exists(removed_role_id));
    EXPECT_TRUE(storage.exists(retained_role_id));
    EXPECT_FALSE(storage.read<User>(user_id)->granted_roles.isGranted(removed_role_id));
}
