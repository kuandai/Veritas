#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

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
class RedisTokenStore final : public TokenStore {
 public:
  explicit RedisTokenStore(std::string uri);

  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::string uri_;
  std::unique_ptr<class RedisClient> redis_;
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
