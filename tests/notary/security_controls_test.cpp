#include "security_controls.h"

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace veritas::notary {
namespace {

TEST(SecurityControlsTest, RevokedTokenTrackerCrossesThresholdOnce) {
  RevokedTokenAbusePolicy policy;
  policy.threshold = 3;
  policy.window = std::chrono::seconds(5);
  policy.enforcement_enabled = false;
  RevokedTokenAbuseTracker tracker(policy);

  const auto first = tracker.RecordAttempt("token-a");
  const auto second = tracker.RecordAttempt("token-a");
  const auto third = tracker.RecordAttempt("token-a");
  const auto fourth = tracker.RecordAttempt("token-a");

  EXPECT_FALSE(first.threshold_crossed);
  EXPECT_FALSE(second.threshold_crossed);
  EXPECT_TRUE(third.threshold_crossed);
  EXPECT_FALSE(third.enforcement_activated);
  EXPECT_FALSE(fourth.threshold_crossed);
  EXPECT_FALSE(tracker.IsContainmentActive());
}

TEST(SecurityControlsTest, RevokedTokenTrackerWindowExpiryResetsThreshold) {
  RevokedTokenAbusePolicy policy;
  policy.threshold = 2;
  policy.window = std::chrono::milliseconds(120);
  policy.enforcement_enabled = false;
  RevokedTokenAbuseTracker tracker(policy);

  EXPECT_FALSE(tracker.RecordAttempt("token-b").threshold_crossed);
  EXPECT_TRUE(tracker.RecordAttempt("token-b").threshold_crossed);

  std::this_thread::sleep_for(std::chrono::milliseconds(180));
  const auto after_window = tracker.RecordAttempt("token-b");
  EXPECT_FALSE(after_window.threshold_crossed);
  EXPECT_EQ(after_window.attempts_in_window, 1U);
}

TEST(SecurityControlsTest, RevokedTokenTrackerActivatesContainmentWhenEnabled) {
  RevokedTokenAbusePolicy policy;
  policy.threshold = 1;
  policy.window = std::chrono::seconds(5);
  policy.enforcement_enabled = true;
  policy.enforcement_duration = std::chrono::milliseconds(200);
  RevokedTokenAbuseTracker tracker(policy);

  const auto result = tracker.RecordAttempt("token-c");
  EXPECT_TRUE(result.threshold_crossed);
  EXPECT_TRUE(result.enforcement_activated);
  EXPECT_TRUE(tracker.IsContainmentActive());

  std::this_thread::sleep_for(std::chrono::milliseconds(260));
  EXPECT_FALSE(tracker.IsContainmentActive());
}

}  // namespace
}  // namespace veritas::notary
