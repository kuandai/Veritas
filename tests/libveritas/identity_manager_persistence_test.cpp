#include "veritas/identity_manager.h"

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

#include <gtest/gtest.h>

namespace veritas {
namespace {

std::filesystem::path UniqueTempFile(const std::string& suffix) {
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() /
         ("veritas_identity_manager_" + std::to_string(now) + "_" + suffix);
}

TEST(IdentityManagerPersistenceTest, LoadsPersistedIdentityAtStartup) {
  storage::TokenStoreConfig config;
  config.backend = storage::TokenStoreBackend::File;
  config.file_path = UniqueTempFile("startup").string();
  config.allow_insecure_fallback = true;

  auto store = storage::CreateTokenStore(config);
  storage::StoredIdentity seeded;
  seeded.user_uuid = "seed-user";
  seeded.refresh_token = "seed-token";
  seeded.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'123));
  store->Save(seeded);

  IdentityManager manager([] { return std::string("unused"); }, config);
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::None);
  const std::optional<AuthResult> loaded = manager.GetPersistedIdentity();
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->user_uuid, seeded.user_uuid);
  EXPECT_EQ(loaded->refresh_token, seeded.refresh_token);
  EXPECT_EQ(
      std::chrono::duration_cast<std::chrono::seconds>(
          loaded->expires_at.time_since_epoch())
          .count(),
      std::chrono::duration_cast<std::chrono::seconds>(
          seeded.expires_at.time_since_epoch())
          .count());
}

TEST(IdentityManagerPersistenceTest, ClearPersistedIdentityRemovesStoredValue) {
  storage::TokenStoreConfig config;
  config.backend = storage::TokenStoreBackend::File;
  config.file_path = UniqueTempFile("clear").string();
  config.allow_insecure_fallback = true;

  auto store = storage::CreateTokenStore(config);
  storage::StoredIdentity seeded;
  seeded.user_uuid = "clear-user";
  seeded.refresh_token = "clear-token";
  seeded.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(1'900'000'456));
  store->Save(seeded);

  IdentityManager manager([] { return std::string("unused"); }, config);
  ASSERT_TRUE(manager.GetPersistedIdentity().has_value());
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);

  manager.ClearPersistedIdentity();
  EXPECT_FALSE(manager.GetPersistedIdentity().has_value());
  EXPECT_EQ(manager.GetState(), IdentityState::Unauthenticated);
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::None);

  auto verify_store = storage::CreateTokenStore(config);
  EXPECT_FALSE(verify_store->Load().has_value());
}

TEST(IdentityManagerStateTest, StartsUnauthenticatedWithoutStoreConfig) {
  IdentityManager manager([] { return std::string("unused"); });
  EXPECT_EQ(manager.GetState(), IdentityState::Unauthenticated);
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::None);
  EXPECT_FALSE(manager.GetPersistedIdentity().has_value());
}

TEST(IdentityManagerStateTest, LockPreventsAuthenticationAttempt) {
  IdentityManager manager([] { return std::string("unused"); });
  manager.Lock();
  EXPECT_EQ(manager.GetState(), IdentityState::Locked);

  GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;

  try {
    static_cast<void>(manager.Authenticate(config, "user", "password"));
    FAIL() << "Authenticate should fail while locked";
  } catch (const IdentityManagerError& ex) {
    EXPECT_EQ(ex.code(), IdentityErrorCode::InvalidStateTransition);
  }
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::InvalidStateTransition);
}

TEST(IdentityManagerStateTest, LockedStateRejectsClearTransition) {
  IdentityManager manager([] { return std::string("unused"); });
  manager.Lock();
  EXPECT_EQ(manager.GetState(), IdentityState::Locked);

  try {
    manager.ClearPersistedIdentity();
    FAIL() << "ClearPersistedIdentity should fail while locked";
  } catch (const IdentityManagerError& ex) {
    EXPECT_EQ(ex.code(), IdentityErrorCode::InvalidStateTransition);
  }
  EXPECT_EQ(manager.GetState(), IdentityState::Locked);
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::InvalidStateTransition);
}

TEST(IdentityManagerStateTest, MissingCredentialProviderHasMachineReadableError) {
  IdentityManager manager(CredentialProvider{});
  GatekeeperClientConfig config;
  try {
    static_cast<void>(manager.Authenticate(config, "user"));
    FAIL() << "Authenticate should fail when credential provider is missing";
  } catch (const IdentityManagerError& ex) {
    EXPECT_EQ(ex.code(), IdentityErrorCode::MissingCredentialProvider);
  }
  EXPECT_EQ(manager.GetLastError(), IdentityErrorCode::MissingCredentialProvider);
}

}  // namespace
}  // namespace veritas
