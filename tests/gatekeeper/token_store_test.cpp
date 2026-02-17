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

TEST(TokenStoreTest, ParseRedisUriParsesBasicFields) {
  const auto config =
      ParseRedisConnectionConfig("redis://:secret@cache.internal:6380/2");
  EXPECT_FALSE(config.use_tls);
  EXPECT_EQ(config.host, "cache.internal");
  EXPECT_EQ(config.port, 6380);
  EXPECT_EQ(config.db, 2);
  EXPECT_EQ(config.password, "secret");
}

TEST(TokenStoreTest, ParseRedissUriRequiresCaWhenVerifyPeerEnabled) {
  EXPECT_THROW(
      ParseRedisConnectionConfig("rediss://cache.internal:6380/0"),
      TokenStoreError);
}

TEST(TokenStoreTest, ParseRedissUriParsesTlsOptions) {
  const auto config = ParseRedisConnectionConfig(
      "rediss://alice:secret@cache.internal:6380/1"
      "?cacert=/etc/ssl/certs/ca.pem&cert=/tmp/client.crt&key=/tmp/client.key"
      "&sni=redis.example.internal&verify_peer=true");
  EXPECT_TRUE(config.use_tls);
  EXPECT_TRUE(config.tls_verify_peer);
  EXPECT_EQ(config.username, "alice");
  EXPECT_EQ(config.password, "secret");
  EXPECT_EQ(config.tls_ca_cert_path, "/etc/ssl/certs/ca.pem");
  EXPECT_EQ(config.tls_cert_path, "/tmp/client.crt");
  EXPECT_EQ(config.tls_key_path, "/tmp/client.key");
  EXPECT_EQ(config.tls_sni, "redis.example.internal");
}

TEST(TokenStoreTest, ParseRedissUriAllowsExplicitVerifyPeerDisable) {
  const auto config = ParseRedisConnectionConfig(
      "rediss://cache.internal:6380/0?verify_peer=false");
  EXPECT_TRUE(config.use_tls);
  EXPECT_FALSE(config.tls_verify_peer);
  EXPECT_TRUE(config.tls_ca_cert_path.empty());
}

TEST(TokenStoreTest, ParseRedisUriRejectsTlsParamsWithoutRediss) {
  EXPECT_THROW(
      ParseRedisConnectionConfig(
          "redis://cache.internal:6379/0?cacert=/etc/ssl/certs/ca.pem"),
      TokenStoreError);
}

}  // namespace veritas::gatekeeper
