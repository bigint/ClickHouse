#include <Access/ExternalAuthenticators.h>
#include <Common/Exception.h>
#include <Common/Logger.h>

#include <gtest/gtest.h>
#include <Poco/AutoPtr.h>
#include <Poco/Util/XMLConfiguration.h>

#include <sstream>


namespace DB
{

struct ExternalAuthenticatorsTestAccess
{
    static HTTPAuthClientParams getHTTPAuthenticationParams(const ExternalAuthenticators & authenticators, const String & server)
    {
        return authenticators.getHTTPAuthenticationParams(server);
    }
};

namespace
{
    Poco::AutoPtr<Poco::Util::XMLConfiguration> createConfig(const String & xml)
    {
        std::istringstream stream(xml);
        Poco::AutoPtr<Poco::Util::XMLConfiguration> config = new Poco::Util::XMLConfiguration(stream);
        return config;
    }
}

TEST(ExternalAuthenticators, ResetRemovesHTTPServers)
{
    ExternalAuthenticators authenticators;
    const auto config = createConfig(R"(
        <clickhouse>
            <http_authentication_servers>
                <primary>
                    <uri>http://127.0.0.1:1/authenticate</uri>
                </primary>
            </http_authentication_servers>
        </clickhouse>
    )");
    authenticators.setConfiguration(*config, getLogger("ExternalAuthenticatorsResetTest"));
    EXPECT_EQ(
        ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary").uri.toString(),
        "http://127.0.0.1:1/authenticate");

    authenticators.reset();
    EXPECT_THROW(ExternalAuthenticatorsTestAccess::getHTTPAuthenticationParams(authenticators, "primary"), Exception);
}

}
