#include "session_cache.h"

#include <chrono>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(SessionCacheTest, InsertGetErase) {
  SessionCache cache(std::chrono::seconds(5));
  SrpSession session;
  session.session_id = "session-1";
  session.login_username = "alice";
  session.expires_at = std::chrono::system_clock::now() +
                       std::chrono::seconds(5);

  cache.Insert(session);
  const auto found = cache.Get("session-1");
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(found->login_username, "alice");

  cache.Erase("session-1");
  EXPECT_FALSE(cache.Get("session-1").has_value());
}

TEST(SessionCacheTest, CleanupExpiredRemovesEntries) {
  SessionCache cache(std::chrono::seconds(1));
  SrpSession expired;
  expired.session_id = "expired";
  expired.login_username = "bob";
  expired.expires_at = std::chrono::system_clock::now() -
                       std::chrono::seconds(1);

  cache.Insert(expired);
  cache.CleanupExpired();
  EXPECT_FALSE(cache.Get("expired").has_value());
}

}  // namespace veritas::gatekeeper
