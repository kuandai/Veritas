#include "rate_limiter.h"

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(RateLimiterTest, EnforcesWindowLimit) {
  RateLimiter limiter(2, std::chrono::seconds(1));
  EXPECT_TRUE(limiter.Allow("1.2.3.4"));
  EXPECT_TRUE(limiter.Allow("1.2.3.4"));
  EXPECT_FALSE(limiter.Allow("1.2.3.4"));

  std::this_thread::sleep_for(std::chrono::milliseconds(1100));
  EXPECT_TRUE(limiter.Allow("1.2.3.4"));
}

TEST(RateLimiterTest, SeparatesKeys) {
  RateLimiter limiter(1, std::chrono::seconds(10));
  EXPECT_TRUE(limiter.Allow("1.2.3.4"));
  EXPECT_FALSE(limiter.Allow("1.2.3.4"));
  EXPECT_TRUE(limiter.Allow("5.6.7.8"));
}

TEST(RateLimiterTest, EvictsOldestBucketWhenAtCapacity) {
  RateLimiter limiter(1, std::chrono::seconds(60), 2);
  EXPECT_TRUE(limiter.Allow("ip-a"));
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  EXPECT_TRUE(limiter.Allow("ip-b"));
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  EXPECT_TRUE(limiter.Allow("ip-c"));

  // ip-a should have been evicted to make room for ip-c.
  EXPECT_TRUE(limiter.Allow("ip-a"));
}

}  // namespace veritas::gatekeeper
