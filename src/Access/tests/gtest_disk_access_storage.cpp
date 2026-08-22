#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/AccessEntityIO.h>
#include <Access/DiskAccessStorage.h>
#include <Access/User.h>
#include <Core/UUID.h>
#include <IO/WriteHelpers.h>

#include <Poco/TemporaryFile.h>

#include <chrono>
#include <filesystem>
#include <fstream>


using namespace DB;

namespace
{

void writeEntityToFile(const std::filesystem::path & file_path, const IAccessEntity & entity)
{
    std::ofstream out(file_path);
    out << serializeAccessEntity(entity);
}

void writeNeedRebuildMarker(const String & directory)
{
    std::ofstream{directory + "need_rebuild_lists.mark"};
}

}

TEST(DiskAccessStorageRecovery, RebuildRemovesTempFiles)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    auto stranded_tmp = std::filesystem::path(dir) / (toString(UUIDHelpers::generateV4()) + ".tmp");
    std::ofstream{stranded_tmp} << "text";

    writeNeedRebuildMarker(dir);

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);

    EXPECT_FALSE(std::filesystem::exists(stranded_tmp));
}

TEST(DiskAccessStorageRecovery, RebuildRemovesOlderDuplicates)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    auto user_a = std::make_shared<User>();
    user_a->setName("alice");
    UUID id_a = UUIDHelpers::generateV4();
    auto path_a = std::filesystem::path(dir) / (toString(id_a) + ".sql");
    writeEntityToFile(path_a, *user_a);

    auto user_b = std::make_shared<User>();
    user_b->setName("alice");
    UUID id_b = UUIDHelpers::generateV4();
    auto path_b = std::filesystem::path(dir) / (toString(id_b) + ".sql");
    writeEntityToFile(path_b, *user_b);

    /// Make `path_a` older than `path_b` so the deduplication logic keeps `id_b` and remove `id_a`.
    auto now = std::filesystem::file_time_type::clock::now();
    std::filesystem::last_write_time(path_a, now - std::chrono::seconds(10));
    std::filesystem::last_write_time(path_b, now);

    writeNeedRebuildMarker(dir);

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);

    EXPECT_FALSE(std::filesystem::exists(path_a));
    EXPECT_TRUE(std::filesystem::exists(path_b));

    auto resolved = storage.find<User>("alice");
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, id_b);
}

TEST(DiskAccessStorage, LazyMaterializationDoesNotNotify)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    auto user = std::make_shared<User>();
    user->setName("alice");

    UUID id;
    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        id = storage.insert(user);
    }

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);

    size_t delivered_changes = 0;
    auto subscription = notifier.subscribeForChanges<User>([&](const std::vector<AccessChangesNotifier::Change> & changes)
                                                           { delivered_changes += changes.size(); });

    ASSERT_EQ(storage.read<User>(id)->getName(), "alice");
    notifier.sendNotifications();

    EXPECT_EQ(delivered_changes, 0u);
}

TEST(AccessControl, DiskStorageInitialNotificationsAreDeliveredAfterAttachment)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    auto user = std::make_shared<User>();
    user->setName("alice");
    const auto id = UUIDHelpers::generateV4();
    writeEntityToFile(std::filesystem::path(dir) / (toString(id) + ".sql"), *user);
    writeNeedRebuildMarker(dir);

    AccessControl access_control;
    bool entity_visible_during_notification = false;
    auto subscription = access_control.subscribeForChanges<User>(
        [&](const std::vector<AccessChangesNotifier::Change> & changes)
        {
            if (!changes.empty())
                entity_visible_during_notification = access_control.find<User>("alice").has_value();
        });

    access_control.addDiskStorage("test_disk", dir, /*readonly_=*/false, /*allow_backup_=*/false);

    EXPECT_TRUE(entity_visible_during_notification);
}
