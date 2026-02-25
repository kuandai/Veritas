#include "veritas/storage/token_store.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
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

std::uint32_t ReadMagic(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    throw std::runtime_error("failed to open token-store file");
  }
  unsigned char magic[4] = {0, 0, 0, 0};
  in.read(reinterpret_cast<char*>(magic), sizeof(magic));
  if (in.gcount() != 4) {
    throw std::runtime_error("failed to read token-store magic");
  }
  return (static_cast<std::uint32_t>(magic[0]) << 24) |
         (static_cast<std::uint32_t>(magic[1]) << 16) |
         (static_cast<std::uint32_t>(magic[2]) << 8) |
         static_cast<std::uint32_t>(magic[3]);
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
  config.machine_identity_override = "machine-A";

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

TEST(TokenStoreTest, FileBackendRejectsDifferentMachineIdentity) {
  const auto path = UniqueTempFile("machine_bound");
  TokenStoreConfig save_config;
  save_config.backend = TokenStoreBackend::File;
  save_config.file_path = path.string();
  save_config.allow_insecure_fallback = true;
  save_config.machine_identity_override = "machine-A";

  StoredIdentity expected;
  expected.user_uuid = "user-123";
  expected.refresh_token = "token-abc";
  expected.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'001));

  auto save_store = CreateTokenStore(save_config);
  save_store->Save(expected);

  TokenStoreConfig load_config = save_config;
  load_config.machine_identity_override = "machine-B";
  auto load_store = CreateTokenStore(load_config);
  EXPECT_THROW(static_cast<void>(load_store->Load()), TokenStoreError);
}

TEST(TokenStoreTest, FileBackendRejectsCorruptedEncryptedPayload) {
  const auto path = UniqueTempFile("corrupt");
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = path.string();
  config.allow_insecure_fallback = true;
  config.machine_identity_override = "machine-A";

  StoredIdentity expected;
  expected.user_uuid = "user-123";
  expected.refresh_token = "token-abc";
  expected.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'002));

  auto store = CreateTokenStore(config);
  store->Save(expected);

  std::ifstream in(path, std::ios::binary);
  ASSERT_TRUE(in.good());
  std::string bytes((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
  ASSERT_GT(bytes.size(), 12U);
  bytes[12] ^= static_cast<char>(0x7f);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(out.good());
  out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  out.close();

  EXPECT_THROW(static_cast<void>(store->Load()), TokenStoreError);
}

TEST(TokenStoreTest, FileBackendMigratesLegacyPlaintextPayload) {
  const auto path = UniqueTempFile("migration");
  TokenStoreConfig legacy_config;
  legacy_config.backend = TokenStoreBackend::File;
  legacy_config.file_path = path.string();
  legacy_config.allow_insecure_fallback = true;
  legacy_config.break_glass_plaintext_file = true;
  legacy_config.machine_identity_override = "machine-A";

  StoredIdentity expected;
  expected.user_uuid = "user-legacy";
  expected.refresh_token = "legacy-token";
  expected.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'003));

  auto legacy_store = CreateTokenStore(legacy_config);
  legacy_store->Save(expected);
  EXPECT_EQ(ReadMagic(path), 0x56545331U);

  TokenStoreConfig secure_config = legacy_config;
  secure_config.break_glass_plaintext_file = false;
  secure_config.migrate_legacy_plaintext = true;
  auto secure_store = CreateTokenStore(secure_config);
  const auto loaded = secure_store->Load();
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, expected.user_uuid);
  EXPECT_EQ(loaded->refresh_token, expected.refresh_token);
  EXPECT_EQ(ReadMagic(path), 0x56545332U);
}

TEST(TokenStoreTest, FileBackendBreakGlassKeepsPlaintextFormat) {
  const auto path = UniqueTempFile("break_glass");
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = path.string();
  config.allow_insecure_fallback = true;
  config.break_glass_plaintext_file = true;
  config.machine_identity_override = "machine-A";

  StoredIdentity expected;
  expected.user_uuid = "user-break-glass";
  expected.refresh_token = "token-break-glass";
  expected.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'004));

  auto store = CreateTokenStore(config);
  store->Save(expected);
  EXPECT_EQ(ReadMagic(path), 0x56545331U);

  const auto loaded = store->Load();
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, expected.user_uuid);
  EXPECT_EQ(loaded->refresh_token, expected.refresh_token);
}

TEST(TokenStoreTest, FileBackendClearIsIdempotent) {
  const auto path = UniqueTempFile("clear");
  TokenStoreConfig config;
  config.backend = TokenStoreBackend::File;
  config.file_path = path.string();
  config.allow_insecure_fallback = true;
  config.machine_identity_override = "machine-A";

  auto store = CreateTokenStore(config);
  ASSERT_NE(store, nullptr);
  EXPECT_NO_THROW(store->Clear());
  EXPECT_NO_THROW(store->Clear());
}

}  // namespace
}  // namespace veritas::storage
