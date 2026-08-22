#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/MultipleAccessStorage.h>
#include <Access/Role.h>
#include <Access/User.h>
#include <Common/Exception.h>


using namespace DB;

namespace
{

AccessEntityPtr makeUser(const String & name)
{
    auto user = std::make_shared<User>();
    user->setName(name);
    return user;
}

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
