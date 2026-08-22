#include <gtest/gtest.h>
#include <Access/ReplicatedAccessStorage.h>
#include <Access/AccessChangesNotifier.h>

using namespace DB;

namespace DB
{
namespace ErrorCodes
{
    extern const int BAD_ARGUMENTS;
    extern const int NO_ZOOKEEPER;
}
}


TEST(ReplicatedAccessStorage, ShutdownWithFailedStartup)
{
    auto get_zk = []()
    {
        return std::shared_ptr<zkutil::ZooKeeper>();
    };

    AccessChangesNotifier changes_notifier;

    try
    {
        auto storage = ReplicatedAccessStorage("replicated", "/clickhouse/access", get_zk, changes_notifier, false, false);
    }
    catch (Exception & e)
    {
        if (e.code() != ErrorCodes::NO_ZOOKEEPER)
            throw;
    }
}

TEST(ReplicatedAccessStorage, RejectsZooKeeperRootPath)
{
    auto get_zk = []()
    {
        return std::shared_ptr<zkutil::ZooKeeper>();
    };

    AccessChangesNotifier changes_notifier;

    try
    {
        auto storage = ReplicatedAccessStorage("replicated", "/", get_zk, changes_notifier, false, false);
        FAIL() << "Expected the ZooKeeper root path to be rejected";
    }
    catch (const Exception & e)
    {
        EXPECT_EQ(ErrorCodes::BAD_ARGUMENTS, e.code());
    }
}
