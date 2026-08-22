#include <gtest/gtest.h>

#include <Access/Common/AllowedClientHosts.h>
#include <Common/Exception.h>


using namespace DB;

TEST(AllowedClientHosts, IPv6LikePatternAllowsShortFirstGroup)
{
    AllowedClientHosts hosts;
    hosts.addLikePattern("65:ff0c::/96");

    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"65:ff0c::1"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"65:ff0d::1"}));
}

TEST(AllowedClientHosts, IPv6WildcardAllowsShortFirstGroup)
{
    AllowedClientHosts hosts;
    hosts.addLikePattern("a::%");

    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"a::1234"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"b::1234"}));
}

TEST(AllowedClientHosts, IPv6WildcardsMatchAddressText)
{
    AllowedClientHosts hosts;
    hosts.addLikePattern("2001:db8:1%::");
    hosts.addLikePattern("2001:db8:_::1");

    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"2001:db8:1234::"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"2001:db8:2::"}));
    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"2001:db8:a::1"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"2001:db8:ab::1"}));
}

TEST(AllowedClientHosts, IPv4WildcardsMatchAddressText)
{
    AllowedClientHosts hosts;
    hosts.addLikePattern("192.168.1_.2");
    hosts.addLikePattern("198.51.1%.3");
    hosts.addLikePattern("_92.0.2.4");

    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"192.168.15.2"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"192.168.5.2"}));
    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"198.51.100.3"}));
    EXPECT_FALSE(hosts.contains(AllowedClientHosts::IPAddress{"198.51.200.3"}));
    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"192.0.2.4"}));
    EXPECT_TRUE(hosts.contains(AllowedClientHosts::IPAddress{"::ffff:192.168.15.2"}));
}

TEST(AllowedClientHosts, RejectsInvalidNameRegexpEagerly)
{
    AllowedClientHosts hosts;

    EXPECT_THROW(hosts.addNameRegexp("["), Exception);
    EXPECT_TRUE(hosts.empty());
}

TEST(AllowedClientHosts, RejectsPrefixLengthsBeforeNarrowing)
{
    EXPECT_THROW(AllowedClientHosts::IPSubnet{"192.0.2.1/4294967296"}, Exception);
    EXPECT_THROW(AllowedClientHosts::IPSubnet{"192.0.2.1/33"}, Exception);
    EXPECT_THROW(AllowedClientHosts::IPSubnet{"2001:db8::1/129"}, Exception);
    EXPECT_THROW(AllowedClientHosts::IPSubnet{"192.0.2.1/"}, Exception);
}
