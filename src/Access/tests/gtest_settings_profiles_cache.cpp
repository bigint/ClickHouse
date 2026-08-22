#include <gtest/gtest.h>

#include <Access/AccessChangesNotifier.h>
#include <Access/AccessControl.h>
#include <Access/EnabledSettings.h>
#include <Access/MemoryAccessStorage.h>
#include <Access/SettingsConstraintsAndProfileIDs.h>
#include <Access/SettingsProfile.h>
#include <Access/SettingsProfilesInfo.h>
#include <Core/Settings.h>
#include <Core/UUID.h>
#include <Parsers/Access/ASTSettingsProfileElement.h>


using namespace DB;

TEST(SettingsProfileElement, CastsDisallowedValuesWithoutOverwritingValue)
{
    AccessControl access_control;
    ASTSettingsProfileElement ast;
    ast.setting_name = "max_memory_usage";
    ast.value = Field{String{"7"}};
    ast.disallowed_values = {Field{String{"1"}}, Field{String{"2"}}};

    SettingsProfileElement element{ast, access_control};

    ASSERT_TRUE(element.value.has_value());
    EXPECT_EQ(element.value->safeGet<UInt64>(), 7);
    ASSERT_EQ(element.disallowed_values.size(), 2);
    EXPECT_EQ(element.disallowed_values[0].safeGet<UInt64>(), 1);
    EXPECT_EQ(element.disallowed_values[1].safeGet<UInt64>(), 2);
}

TEST(SettingsProfileElement, MapDisallowedValueRoundTripsThroughAST)
{
    SettingsProfileElement original;
    original.setting_name = "http_response_headers";
    original.disallowed_values = {Field{Map{Tuple{String{"X-Test"}, String{"value"}}}}};

    const auto ast = original.toAST();
    ASSERT_EQ(ast->disallowed_values.size(), 1);
    EXPECT_EQ(ast->disallowed_values.front().getType(), Field::Types::String);

    const SettingsProfileElement restored{*ast};
    EXPECT_EQ(restored.disallowed_values, original.disallowed_values);
}

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

TEST(SettingsProfilesCache, DefaultProfileTracksConfiguredName)
{
    AccessControl access_control;
    auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
    access_control.setStorages({storage});

    auto original_profile = std::make_shared<SettingsProfile>();
    original_profile->setName("configured");
    const auto original_id = access_control.insert(original_profile);

    access_control.setDefaultProfileName("configured");
    auto enabled_settings = access_control.getEnabledSettings(UUIDHelpers::generateV4(), {}, {}, {});
    EXPECT_EQ(std::vector<UUID>{original_id}, enabled_settings->getInfo()->profiles_with_implicit);

    access_control.update(
        original_id,
        [](const AccessEntityPtr & entity, const UUID &)
        {
            auto renamed_profile = std::static_pointer_cast<SettingsProfile>(entity->clone());
            renamed_profile->setName("renamed");
            return renamed_profile;
        });
    EXPECT_TRUE(enabled_settings->getInfo()->profiles_with_implicit.empty());

    auto replacement_profile = std::make_shared<SettingsProfile>();
    replacement_profile->setName("configured");
    const auto replacement_id = access_control.insert(replacement_profile);
    EXPECT_EQ(std::vector<UUID>{replacement_id}, enabled_settings->getInfo()->profiles_with_implicit);
}

TEST(SettingsProfilesCache, EnabledSettingsOutlivesAccessControl)
{
    std::shared_ptr<const EnabledSettings> enabled_settings;
    {
        AccessControl access_control;
        auto storage = std::make_shared<MemoryAccessStorage>("memory", access_control.getChangesNotifier(), true);
        access_control.setStorages({storage});

        auto profile = std::make_shared<SettingsProfile>();
        profile->setName("retained");
        const auto profile_id = access_control.insert(profile);

        SettingsProfileElements settings_from_user;
        settings_from_user.emplace_back().parent_profile = profile_id;
        enabled_settings = access_control.getEnabledSettings(UUIDHelpers::generateV4(), settings_from_user, {}, {});
    }

    const auto info = enabled_settings->getInfo();
    EXPECT_EQ(Strings{"retained"}, info->getProfileNames());

    const auto first_constraints = info->getConstraintsAndProfileIDs();
    EXPECT_NO_THROW(info->getConstraintsAndProfileIDs(first_constraints));

    Settings settings;
    SettingsChanges changes{{"max_threads", Field{UInt64{1}}}};
    EXPECT_NO_THROW(first_constraints->constraints.check(settings, changes, SettingSource::QUERY));
}
