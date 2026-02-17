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

namespace veritas::gatekeeper {

struct TokenRecord {
  std::string token_hash;
  std::string user_uuid;
  std::chrono::system_clock::time_point expires_at;
  bool is_revoked = false;
};

class TokenStore {
 public:
  virtual ~TokenStore() = default;

  virtual void PutToken(const TokenRecord& record) = 0;
  virtual std::optional<TokenRecord> GetToken(const std::string& token_hash) = 0;
  virtual void RevokeUser(const std::string& user_uuid) = 0;
};

class TokenStoreError : public std::runtime_error {
 public:
  enum class Kind {
    Unavailable,
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
  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::mutex mutex_;
  std::unordered_map<std::string, TokenRecord> tokens_;
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
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::string uri_;
};
#endif

}  // namespace veritas::gatekeeper
