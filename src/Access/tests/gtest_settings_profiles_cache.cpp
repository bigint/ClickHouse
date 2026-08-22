#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledSettings.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/SettingsProfile.h>
#include <Access/SettingsProfilesInfo.h>
#include <Core/UUID.h>


using namespace DB;

TEST(SettingsProfilesCache, DefaultProfileChangeRefreshesExistingEnabledSettings)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto first_profile = std::make_shared<SettingsProfile>();
    first_profile->setName("first");
    const auto first_id = access_control.insert(first_profile);

    auto second_profile = std::make_shared<SettingsProfile>();
    second_profile->setName("second");
    const auto second_id = access_control.insert(second_profile);

    access_control.setDefaultProfileName("first");
    auto enabled_settings = access_control.getEnabledSettings(UUIDHelpers::generateV4(), {}, {}, {});
    auto info = enabled_settings->getInfo();
    ASSERT_EQ(1u, info->profiles_with_implicit.size());
    EXPECT_EQ(first_id, info->profiles_with_implicit.front());

    access_control.setDefaultProfileName("second");
    info = enabled_settings->getInfo();
    ASSERT_EQ(1u, info->profiles_with_implicit.size());
    EXPECT_EQ(second_id, info->profiles_with_implicit.front());

    access_control.setDefaultProfileName("");
    EXPECT_TRUE(enabled_settings->getInfo()->profiles_with_implicit.empty());
}
