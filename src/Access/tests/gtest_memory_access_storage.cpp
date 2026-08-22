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
