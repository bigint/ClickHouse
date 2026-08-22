#include <Access/AccessControl.h>

#include <gtest/gtest.h>

using namespace DB;

TEST(SettingsConstraintsPolicy, EmptyCommaSeparatedPrefixesDoNotAllowAllSettings)
{
    AccessControl access_control;
    access_control.setCustomSettingsPrefixes(",custom_,,");

    EXPECT_TRUE(access_control.isSettingNameAllowed("custom_value"));
    EXPECT_FALSE(access_control.isSettingNameAllowed("unregistered_value"));

    access_control.allowAllSettings();
    EXPECT_TRUE(access_control.isSettingNameAllowed("unregistered_value"));
}
