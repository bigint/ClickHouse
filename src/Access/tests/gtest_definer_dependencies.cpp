#include <Access/DefinerDependencies.h>

#include <Core/UUID.h>
#include <gtest/gtest.h>

using namespace DB;

TEST(DefinerDependencies, ReassigningObjectRemovesOldDefinerMapping)
{
    auto & dependencies = DefinerDependencies::instance();
    const StorageID object_id{"database", "object", UUIDHelpers::generateV4()};

    dependencies.addDependency("old_definer", object_id);
    dependencies.addDependency("new_definer", object_id);

    EXPECT_FALSE(dependencies.hasDependencies("old_definer"));
    EXPECT_EQ(dependencies.getObjectsForDefiner("new_definer"), std::vector{object_id.uuid});

    dependencies.removeDependencies(object_id);
}
