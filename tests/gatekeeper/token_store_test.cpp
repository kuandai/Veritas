#include "token_store.h"

#include <chrono>
#include <string>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(TokenStoreTest, InMemoryStorePutGet) {
  InMemoryTokenStore store;
  TokenRecord record;
  record.token_hash = "hash";
  record.user_uuid = "user";
  record.expires_at = std::chrono::system_clock::now() +
                      std::chrono::hours(1);

  store.PutToken(record);
  const auto loaded = store.GetToken("hash");
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, "user");
  EXPECT_FALSE(loaded->is_revoked);
}

TEST(TokenStoreTest, InMemoryStoreRevokeUserMarksTokens) {
  InMemoryTokenStore store;
  TokenRecord record;
  record.token_hash = "hash";
  record.user_uuid = "user";
  record.expires_at = std::chrono::system_clock::now() +
                      std::chrono::hours(1);

  store.PutToken(record);
  store.RevokeUser("user");

  const auto loaded = store.GetToken("hash");
  ASSERT_TRUE(loaded.has_value());
  EXPECT_TRUE(loaded->is_revoked);
}

TEST(TokenStoreTest, RedisStoreDisabledThrows) {
  EXPECT_THROW(RedisTokenStore("redis://localhost:6379/0"), TokenStoreError);
}

}  // namespace veritas::gatekeeper
