#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

#if !defined(VERITAS_DISABLE_REDIS)
#include <sw/redis++/redis++.h>
#endif

namespace veritas::shared {

struct TokenRecord {
  std::string token_hash;
  std::string user_uuid;
  std::chrono::system_clock::time_point expires_at;
  bool is_revoked = false;
  std::string revoke_reason;
  std::chrono::system_clock::time_point revoked_at{};
};

enum class TokenState {
  Unknown,
  Active,
  Revoked,
};

struct TokenStatus {
  TokenState state = TokenState::Unknown;
  std::string user_uuid;
  std::string reason;
  std::chrono::system_clock::time_point revoked_at{};
};

class TokenStore {
 public:
  virtual ~TokenStore() = default;

  virtual void PutToken(const TokenRecord& record) = 0;
  virtual std::optional<TokenRecord> GetToken(const std::string& token_hash) = 0;
  virtual TokenStatus GetTokenStatus(const std::string& token_hash) = 0;
  virtual void RevokeToken(const std::string& token_hash,
                           const std::string& reason) = 0;
  virtual void RevokeUser(const std::string& user_uuid) = 0;
};

class TokenStoreError : public std::runtime_error {
 public:
  enum class Kind {
    Unavailable,
    ReplayRejected,
  };

  TokenStoreError(Kind kind, const std::string& message);

  Kind kind() const noexcept { return kind_; }

 private:
  Kind kind_;
};

struct RedisConnectionConfig {
  std::string host;
  int port = 6379;
  int db = 0;
  std::string username;
  std::string password;
  bool use_tls = false;
  bool tls_verify_peer = true;
  std::string tls_ca_cert_path;
  std::string tls_ca_cert_dir;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string tls_sni;
};

RedisConnectionConfig ParseRedisConnectionConfig(const std::string& uri);

class InMemoryTokenStore final : public TokenStore {
 public:
  explicit InMemoryTokenStore(
      std::chrono::seconds tombstone_ttl = std::chrono::hours(24))
      : tombstone_ttl_(tombstone_ttl) {}

  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  TokenStatus GetTokenStatus(const std::string& token_hash) override;
  void RevokeToken(const std::string& token_hash,
                   const std::string& reason) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  struct TombstoneRecord {
    std::string user_uuid;
    std::string reason;
    std::chrono::system_clock::time_point revoked_at{};
    std::chrono::system_clock::time_point expires_at{};
  };

  void CleanupExpiredLocked();

  std::mutex mutex_;
  std::chrono::seconds tombstone_ttl_;
  std::unordered_map<std::string, TokenRecord> tokens_;
  std::unordered_map<std::string, TombstoneRecord> tombstones_;
};

#if !defined(VERITAS_DISABLE_REDIS)
class RedisClient {
 public:
  explicit RedisClient(const sw::redis::ConnectionOptions& options)
      : redis(options) {}

  sw::redis::Redis redis;
};

class RedisTokenStore final : public TokenStore {
 public:
  explicit RedisTokenStore(std::string uri);

  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  TokenStatus GetTokenStatus(const std::string& token_hash) override;
  void RevokeToken(const std::string& token_hash,
                   const std::string& reason) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::string uri_;
  std::unique_ptr<RedisClient> redis_;
};
#else
class RedisTokenStore final : public TokenStore {
 public:
  explicit RedisTokenStore(std::string uri);

  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  TokenStatus GetTokenStatus(const std::string& token_hash) override;
  void RevokeToken(const std::string& token_hash,
                   const std::string& reason) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::string uri_;
};
#endif

}  // namespace veritas::shared
