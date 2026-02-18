#include "veritas/storage/token_store.h"

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

#include <gtest/gtest.h>

namespace veritas::storage {
namespace {

std::filesystem::path UniqueTempFile(const std::string& suffix) {
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() /
         ("veritas_token_store_" + std::to_string(now) + "_" + suffix);
}

TEST(TokenStoreTest, FileBackendRequiresExplicitOptIn) {
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = UniqueTempFile("deny").string();
  config.allow_insecure_fallback = false;

  EXPECT_THROW(static_cast<void>(CreateTokenStore(config)), TokenStoreError);
}

TEST(TokenStoreTest, FileBackendRoundTripsBinaryToken) {
  const auto path = UniqueTempFile("roundtrip");
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = path.string();
  config.allow_insecure_fallback = true;

  auto store = CreateTokenStore(config);
  ASSERT_NE(store, nullptr);

  StoredIdentity expected;
  expected.user_uuid = "user-123";
  expected.refresh_token = std::string("\0\x01\x7ftoken-data", 13);
  expected.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'000));

  store->Save(expected);
  const std::optional<StoredIdentity> loaded = store->Load();

  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, expected.user_uuid);
  EXPECT_EQ(loaded->refresh_token, expected.refresh_token);
  EXPECT_EQ(
      std::chrono::duration_cast<std::chrono::seconds>(
          loaded->expires_at.time_since_epoch())
          .count(),
      std::chrono::duration_cast<std::chrono::seconds>(
          expected.expires_at.time_since_epoch())
          .count());

  store->Clear();
  EXPECT_FALSE(store->Load().has_value());
}

TEST(TokenStoreTest, FileBackendClearIsIdempotent) {
  const auto path = UniqueTempFile("clear");
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = path.string();
  config.allow_insecure_fallback = true;

  auto store = CreateTokenStore(config);
  ASSERT_NE(store, nullptr);
  EXPECT_NO_THROW(store->Clear());
  EXPECT_NO_THROW(store->Clear());
}

}  // namespace
}  // namespace veritas::storage
