#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace veritas::storage {

struct StoredIdentity {
  std::string user_uuid;
  std::string refresh_token;
  std::chrono::system_clock::time_point expires_at{};
};

enum class TokenStoreBackend {
  Libsecret,
  File,
};

struct TokenStoreConfig {
  TokenStoreBackend backend = TokenStoreBackend::Libsecret;
  std::string service_name = "veritas";
  std::string account_name = "default";
  std::string file_path;
  bool allow_insecure_fallback = false;
};

class TokenStoreError : public std::runtime_error {
 public:
  explicit TokenStoreError(const std::string& message)
      : std::runtime_error(message) {}
};

class TokenStore {
 public:
  virtual ~TokenStore() = default;

  virtual void Save(const StoredIdentity& identity) = 0;
  virtual std::optional<StoredIdentity> Load() = 0;
  virtual void Clear() = 0;
};

std::unique_ptr<TokenStore> CreateTokenStore(const TokenStoreConfig& config);

}  // namespace veritas::storage
