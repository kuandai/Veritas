#include "auth_metrics.h"

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(AuthMetricsTest, TracksSuccessAndFailureCounters) {
  AuthMetrics metrics;
  metrics.Record("1.2.3.4", "user-a", true);
  metrics.Record("1.2.3.4", "user-a", false);

  const auto ip_counter = metrics.GetIpCounter("1.2.3.4");
  ASSERT_TRUE(ip_counter.has_value());
  EXPECT_EQ(ip_counter->success, 1u);
  EXPECT_EQ(ip_counter->failure, 1u);

  const auto uuid_counter = metrics.GetUuidCounter("user-a");
  ASSERT_TRUE(uuid_counter.has_value());
  EXPECT_EQ(uuid_counter->success, 1u);
  EXPECT_EQ(uuid_counter->failure, 1u);
}

TEST(AuthMetricsTest, BoundsKeyCardinalityWithEviction) {
  AuthMetrics metrics(2, 2);
  metrics.Record("ip-1", "user-1", true);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  metrics.Record("ip-2", "user-2", true);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  metrics.Record("ip-3", "user-3", true);

  EXPECT_LE(metrics.IpKeyCount(), 2u);
  EXPECT_LE(metrics.UuidKeyCount(), 2u);
  EXPECT_FALSE(metrics.GetIpCounter("ip-1").has_value());
  EXPECT_FALSE(metrics.GetUuidCounter("user-1").has_value());
  EXPECT_TRUE(metrics.GetIpCounter("ip-3").has_value());
  EXPECT_TRUE(metrics.GetUuidCounter("user-3").has_value());
}

TEST(AuthMetricsTest, TracksSecurityEventCounters) {
  AuthMetrics metrics;
  metrics.RecordSecurityEvent("token_revoked");
  metrics.RecordSecurityEvent("token_revoked");
  metrics.RecordSecurityEvent("auth_failure");

  EXPECT_EQ(metrics.SecurityEventCount("token_revoked"), 2u);
  EXPECT_EQ(metrics.SecurityEventCount("auth_failure"), 1u);
  EXPECT_EQ(metrics.SecurityEventCount("missing"), 0u);
}

}  // namespace veritas::gatekeeper
