#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/MultipleAccessStorage.h>
#include <Access/User.h>


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
