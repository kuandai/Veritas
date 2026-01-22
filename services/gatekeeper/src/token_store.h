#pragma once

#include <chrono>
#include <mutex>
#include <optional>
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

class InMemoryTokenStore final : public TokenStore {
 public:
  void PutToken(const TokenRecord& record) override;
  std::optional<TokenRecord> GetToken(const std::string& token_hash) override;
  void RevokeUser(const std::string& user_uuid) override;

 private:
  std::mutex mutex_;
  std::unordered_map<std::string, TokenRecord> tokens_;
};

}  // namespace veritas::gatekeeper
