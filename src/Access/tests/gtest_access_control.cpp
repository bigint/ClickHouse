#include <Access/AccessControl.h>
#include <Common/Exception.h>

#include <gtest/gtest.h>
#include <Poco/AutoPtr.h>
#include <Poco/Util/XMLConfiguration.h>

#include <sstream>


using namespace DB;

namespace
{
    Poco::AutoPtr<Poco::Util::XMLConfiguration> createConfig(const String & xml)
    {
        std::istringstream stream(xml);
        Poco::AutoPtr<Poco::Util::XMLConfiguration> config = new Poco::Util::XMLConfiguration(stream);
        return config;
    }
}

TEST(AccessControl, InvalidPasswordRulesPreservePreviousPolicy)
{
    AccessControl access_control;
    const auto initial_config = createConfig(R"(
        <clickhouse>
            <password_complexity>
                <rule>
                    <pattern>.{8}</pattern>
                    <message>be at least 8 characters long</message>
                </rule>
            </password_complexity>
        </clickhouse>
    )");
    access_control.setPasswordComplexityRulesFromConfig(*initial_config);
    EXPECT_THROW(access_control.checkPasswordComplexityRules("short"), Exception);

    const auto invalid_replacement = createConfig(R"(
        <clickhouse>
            <password_complexity>
                <rule>
                    <pattern>.*</pattern>
                    <message>match anything</message>
                </rule>
                <rule>
                    <pattern>(</pattern>
                    <message>invalid expression</message>
                </rule>
            </password_complexity>
        </clickhouse>
    )");
    EXPECT_THROW(access_control.setPasswordComplexityRulesFromConfig(*invalid_replacement), Exception);

    EXPECT_THROW(access_control.checkPasswordComplexityRules("short"), Exception);
    EXPECT_NO_THROW(access_control.checkPasswordComplexityRules("long-enough"));
}
