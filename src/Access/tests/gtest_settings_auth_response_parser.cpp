#include <Access/SettingsAuthResponseParser.h>

#include <Poco/Net/HTTPResponse.h>
#include <gtest/gtest.h>

#include <sstream>

using namespace DB;

TEST(SettingsAuthResponseParser, InvalidSettingDiscardsEntireResponsePolicy)
{
    Poco::Net::HTTPResponse response;
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    std::istringstream body{R"({"settings":{"allow_experimental_analyzer":"1","max_threads":"not_a_number"}})"};

    const auto result = SettingsAuthResponseParser{}.parse(response, &body);

    EXPECT_TRUE(result.is_ok);
    EXPECT_TRUE(result.settings.empty());
}
