#include "token_store.h"

#include <chrono>
#include <cstdlib>
#include <random>
#include <string>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {
namespace {

std::string RandomSuffix() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  return std::to_string(dist(gen));
}

TEST(RedisTlsIntegrationTest, RedissWithoutCaFailsClosed) {
  EXPECT_THROW(RedisTokenStore("rediss://127.0.0.1:6379/0"), TokenStoreError);
}

TEST(RedisTlsIntegrationTest, RedissRoundtripWithExternalEndpoint) {
  const char* uri = std::getenv("VERITAS_REDIS_TLS_URI");
  const bool endpoint_required = []() {
    const char* flag = std::getenv("VERITAS_REQUIRE_REDIS_TLS_ENDPOINT");
    return flag && std::string(flag) == "1";
  }();

  if (!uri || uri[0] == '\0') {
    if (endpoint_required) {
      FAIL() << "VERITAS_REDIS_TLS_URI must be set when "
                "VERITAS_REQUIRE_REDIS_TLS_ENDPOINT=1";
    }
    GTEST_SKIP() << "VERITAS_REDIS_TLS_URI is not set";
  }

  RedisTokenStore store(uri);
  TokenRecord record;
  record.token_hash = "integration_hash_" + RandomSuffix();
  record.user_uuid = "integration_user_" + RandomSuffix();
  record.expires_at =
      std::chrono::system_clock::now() + std::chrono::minutes(2);
  record.is_revoked = false;

  store.PutToken(record);
  const auto loaded = store.GetToken(record.token_hash);
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, record.user_uuid);
  EXPECT_FALSE(loaded->is_revoked);
}

}  // namespace
}  // namespace veritas::gatekeeper
