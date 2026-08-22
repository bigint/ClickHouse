#include <gtest/gtest.h>

#include <Access/EnabledQuota.h>

#include <boost/smart_ptr/make_shared.hpp>


namespace DB
{

struct EnabledQuotaTestAccess
{
    struct State
    {
        std::shared_ptr<EnabledQuota> enabled_quota;
        boost::shared_ptr<EnabledQuota::Intervals> intervals;
    };

    static State makeWithExpiredUsage(QuotaValue used)
    {
        EnabledQuota::Params params;
        params.user_name = "user";
        params.client_address = Poco::Net::IPAddress("127.0.0.1");
        auto enabled_quota = std::shared_ptr<EnabledQuota>(new EnabledQuota(params));

        auto intervals = boost::make_shared<EnabledQuota::Intervals>();
        intervals->quota_name = "quota";
        intervals->intervals.emplace_back(std::chrono::seconds(1), false, std::chrono::system_clock::now() - std::chrono::seconds(2));
        auto & interval = intervals->intervals.front();
        constexpr auto queries_index = static_cast<size_t>(QuotaType::QUERIES);
        interval.max[queries_index] = 100;
        interval.used[queries_index] = used;

        auto quota = std::make_unique<EnabledQuota::SingleQuota>();
        quota->intervals = intervals;
        auto quotas = boost::make_shared<EnabledQuota::Quotas>();
        quotas->push_back(std::move(quota));
        enabled_quota->quotas.store(quotas);
        enabled_quota->empty = false;
        return {std::move(enabled_quota), std::move(intervals)};
    }

    static QuotaValue getQueriesUsed(const State & state)
    {
        constexpr auto queries_index = static_cast<size_t>(QuotaType::QUERIES);
        return state.intervals->intervals.front().used[queries_index];
    }
};

TEST(EnabledQuota, ResetsExpiredIntervalBeforeLowUsage)
{
    auto state = EnabledQuotaTestAccess::makeWithExpiredUsage(50);

    state.enabled_quota->used(QuotaType::QUERIES, 1);

    EXPECT_EQ(1, EnabledQuotaTestAccess::getQueriesUsed(state));
}

}
