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

TEST(SessionCacheTest, TakeConsumesSessionAtomically) {
  SessionCache cache(std::chrono::seconds(5));
  SrpSession session;
  session.session_id = "session-1";
  session.login_username = "alice";
  session.expires_at = std::chrono::system_clock::now() +
                       std::chrono::seconds(5);

  cache.Insert(session);

  const auto taken = cache.Take("session-1");
  ASSERT_TRUE(taken.has_value());
  EXPECT_EQ(taken->login_username, "alice");
  EXPECT_FALSE(cache.Get("session-1").has_value());
  EXPECT_FALSE(cache.Take("session-1").has_value());
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

TEST(SessionCacheTest, CompletedSessionCanBeFetchedForReplay) {
  SessionCache cache(std::chrono::seconds(5));
  CompletedSrpSession completed;
  completed.session_id = "session-1";
  completed.client_proof_hash = "proof-hash";
  completed.server_proof = "server-proof";
  completed.user_uuid = "user-1";
  completed.refresh_token = "refresh-1";
  completed.token_expires_at =
      std::chrono::system_clock::now() + std::chrono::hours(1);
  completed.expires_at =
      std::chrono::system_clock::now() + std::chrono::seconds(5);

  cache.InsertCompleted(completed);

  const auto found = cache.GetCompleted("session-1");
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(found->client_proof_hash, "proof-hash");
  EXPECT_EQ(found->refresh_token, "refresh-1");
}

TEST(SessionCacheTest, CleanupExpiredRemovesCompletedEntries) {
  SessionCache cache(std::chrono::seconds(5));
  CompletedSrpSession completed;
  completed.session_id = "expired-completed";
  completed.client_proof_hash = "proof-hash";
  completed.server_proof = "server-proof";
  completed.user_uuid = "user-1";
  completed.refresh_token = "refresh-1";
  completed.token_expires_at =
      std::chrono::system_clock::now() - std::chrono::seconds(10);
  completed.expires_at =
      std::chrono::system_clock::now() - std::chrono::seconds(1);

  cache.InsertCompleted(completed);
  cache.CleanupExpired();
  EXPECT_FALSE(cache.GetCompleted("expired-completed").has_value());
}

}  // namespace veritas::gatekeeper
