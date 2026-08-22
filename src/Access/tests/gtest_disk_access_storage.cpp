#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/AccessEntityIO.h>
#include <Access/DiskAccessStorage.h>
#include <Access/MaskingPolicy.h>
#include <Access/Role.h>
#include <Access/User.h>
#include <Core/UUID.h>
#include <IO/WriteHelpers.h>
#include <Common/Exception.h>
#include <Parsers/ASTLiteral.h>

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

TEST(AccessEntityIO, MaskingPolicyRoundTrip)
{
    MaskingPolicy original;
    original.setFullName("mask", "database", "table");
    original.priority = 7;

    const auto restored = deserializeAccessEntity(serializeAccessEntity(original));

    ASSERT_EQ(restored->getType(), AccessEntityType::MASKING_POLICY);
    EXPECT_EQ(*restored, original);
}

TEST(AccessEntityIO, MaskingPolicyCloneOwnsExpressionTrees)
{
    MaskingPolicy original;
    original.setFullName("mask", "database", "table");
    original.update_assignments = make_intrusive<ASTLiteral>(UInt64{1});
    original.where_condition = make_intrusive<ASTLiteral>(UInt64{2});

    auto cloned = std::static_pointer_cast<MaskingPolicy>(original.clone());

    ASSERT_NE(cloned->update_assignments.get(), original.update_assignments.get());
    ASSERT_NE(cloned->where_condition.get(), original.where_condition.get());
    cloned->update_assignments->as<ASTLiteral &>().value = UInt64{3};
    cloned->where_condition->as<ASTLiteral &>().value = UInt64{4};
    EXPECT_EQ(original.update_assignments->as<const ASTLiteral &>().value, Field{UInt64{1}});
    EXPECT_EQ(original.where_condition->as<const ASTLiteral &>().value, Field{UInt64{2}});
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

TEST(DiskAccessStorageRecovery, RebuildRejectsDuplicatesWithEqualModificationTimes)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    auto user = std::make_shared<User>();
    user->setName("alice");
    auto path_a = std::filesystem::path(dir) / (toString(UUIDHelpers::generateV4()) + ".sql");
    auto path_b = std::filesystem::path(dir) / (toString(UUIDHelpers::generateV4()) + ".sql");
    writeEntityToFile(path_a, *user);
    writeEntityToFile(path_b, *user);

    const auto common_mtime = std::filesystem::file_time_type::clock::now();
    std::filesystem::last_write_time(path_a, common_mtime);
    std::filesystem::last_write_time(path_b, common_mtime);
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(dir) / "need_rebuild_lists.mark"));

    AccessChangesNotifier notifier;
    EXPECT_THROW(
        DiskAccessStorage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false),
        Exception);
    EXPECT_TRUE(std::filesystem::exists(path_a));
    EXPECT_TRUE(std::filesystem::exists(path_b));
    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(dir) / "need_rebuild_lists.mark"));
}

TEST(DiskAccessStorageRecovery, RebuildRejectsUnparsableEntityFiles)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    const auto entity_path
        = std::filesystem::path(dir) / (toString(UUIDHelpers::generateV4()) + ".sql");
    std::ofstream{entity_path} << "not an access entity";

    AccessChangesNotifier notifier;
    EXPECT_THROW(
        DiskAccessStorage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false),
        Exception);
    EXPECT_TRUE(std::filesystem::exists(entity_path));
    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(dir) / "need_rebuild_lists.mark"));
}

TEST(DiskAccessStorageRecovery, RebuildsListWithTrailingGarbage)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    const auto id = UUIDHelpers::generateV4();
    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        auto user = std::make_shared<User>();
        user->setName("alice");
        storage.insert(id, user, false, true);
    }

    const auto users_list_path = std::filesystem::path(dir) / "users.list";
    const auto valid_size = std::filesystem::file_size(users_list_path);
    {
        std::ofstream out(users_list_path, std::ios::app | std::ios::binary);
        out << "garbage";
    }
    ASSERT_GT(std::filesystem::file_size(users_list_path), valid_size);

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
    EXPECT_EQ(storage.getID<User>("alice"), id);
    EXPECT_EQ(std::filesystem::file_size(users_list_path), valid_size);
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

TEST(DiskAccessStorage, ReplacingEntityTypeRewritesBothLists)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    const auto id = UUIDHelpers::generateV4();
    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        auto user = std::make_shared<User>();
        user->setName("entity");
        storage.insert(id, user, false, true);
    }

    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        auto role = std::make_shared<Role>();
        role->setName("entity");
        storage.insert(id, role, true, false);
    }

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
    EXPECT_TRUE(storage.exists(id));
    EXPECT_TRUE(storage.find<Role>("entity").has_value());
    EXPECT_FALSE(storage.find<User>("entity").has_value());
}

TEST(DiskAccessStorage, LazyMaterializationMarksMismatchedListsForRebuild)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    const auto id = UUIDHelpers::generateV4();
    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        auto user = std::make_shared<User>();
        user->setName("alice");
        storage.insert(id, user, false, true);
    }

    auto role = std::make_shared<Role>();
    role->setName("reader");
    writeEntityToFile(std::filesystem::path(dir) / (toString(id) + ".sql"), *role);

    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        EXPECT_THROW(storage.read<User>(id), Exception);
        EXPECT_TRUE(storage.find<User>("alice").has_value());
        EXPECT_FALSE(storage.find<Role>("reader").has_value());
        EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(dir) / "need_rebuild_lists.mark"));
    }

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
    EXPECT_FALSE(storage.find<User>("alice").has_value());
    EXPECT_EQ(storage.getID<Role>("reader"), id);
}

TEST(DiskAccessStorage, LazyUpdateRejectsMismatchedListMetadata)
{
    Poco::TemporaryFile temp_dir;
    temp_dir.createDirectories();
    String dir = temp_dir.path() + "/";

    const auto id = UUIDHelpers::generateV4();
    {
        AccessChangesNotifier notifier;
        DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
        auto user = std::make_shared<User>();
        user->setName("alice");
        storage.insert(id, user, false, true);
    }

    auto role = std::make_shared<Role>();
    role->setName("reader");
    writeEntityToFile(std::filesystem::path(dir) / (toString(id) + ".sql"), *role);

    AccessChangesNotifier notifier;
    DiskAccessStorage storage("test_disk", dir, notifier, /*readonly_=*/false, /*allow_backup_=*/false);
    EXPECT_THROW(storage.update(id, [](const AccessEntityPtr & entity, const UUID &) { return entity; }), Exception);
    EXPECT_TRUE(storage.find<User>("alice").has_value());
    EXPECT_FALSE(storage.find<Role>("reader").has_value());
    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(dir) / "need_rebuild_lists.mark"));
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
