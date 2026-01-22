#include "token_store.h"

#include <chrono>
#include <cstdlib>
#include <memory>
#include <unordered_set>

#if !defined(VERITAS_DISABLE_REDIS)
#include <sw/redis++/redis++.h>
#endif

namespace veritas::gatekeeper {

#if !defined(VERITAS_DISABLE_REDIS)
class RedisClient {
 public:
  explicit RedisClient(const sw::redis::ConnectionOptions& options)
      : redis(options) {}

  sw::redis::Redis redis;
};
#endif

namespace {

#if !defined(VERITAS_DISABLE_REDIS)
sw::redis::ConnectionOptions ParseRedisUri(const std::string& uri) {
  if (uri.rfind("rediss://", 0) == 0) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "rediss:// is not supported yet");
  }

  std::string working = uri;
  if (working.rfind("redis://", 0) == 0) {
    working = working.substr(8);
  }

  std::string password;
  const auto at_pos = working.find('@');
  if (at_pos != std::string::npos) {
    password = working.substr(0, at_pos);
    working = working.substr(at_pos + 1);
    if (!password.empty() && password.front() == ':') {
      password.erase(0, 1);
    }
  }

  int db = 0;
  const auto slash_pos = working.find('/');
  if (slash_pos != std::string::npos) {
    const std::string db_str = working.substr(slash_pos + 1);
    working = working.substr(0, slash_pos);
    if (!db_str.empty()) {
      db = std::stoi(db_str);
    }
  }

  std::string host = working;
  int port = 6379;
  const auto colon_pos = working.rfind(':');
  if (colon_pos != std::string::npos) {
    host = working.substr(0, colon_pos);
    port = std::stoi(working.substr(colon_pos + 1));
  }

  if (host.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis host is empty");
  }

  sw::redis::ConnectionOptions options;
  options.host = host;
  options.port = port;
  options.db = db;
  if (!password.empty()) {
    options.password = password;
  }
  options.connect_timeout = std::chrono::milliseconds(200);
  options.socket_timeout = std::chrono::milliseconds(200);
  return options;
}
#endif

std::string TokenKey(const std::string& token_hash) {
  return "token:" + token_hash;
}

std::string UserTokensKey(const std::string& user_uuid) {
  return "user_tokens:" + user_uuid;
}

}  // namespace

TokenStoreError::TokenStoreError(Kind kind, const std::string& message)
    : std::runtime_error(message), kind_(kind) {}

void InMemoryTokenStore::PutToken(const TokenRecord& record) {
  std::lock_guard<std::mutex> lock(mutex_);
  tokens_[record.token_hash] = record;
}

std::optional<TokenRecord> InMemoryTokenStore::GetToken(
    const std::string& token_hash) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = tokens_.find(token_hash);
  if (it == tokens_.end()) {
    return std::nullopt;
  }
  return it->second;
}

void InMemoryTokenStore::RevokeUser(const std::string& user_uuid) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : tokens_) {
    if (entry.second.user_uuid == user_uuid) {
      entry.second.is_revoked = true;
    }
  }
}

#if !defined(VERITAS_DISABLE_REDIS)
RedisTokenStore::RedisTokenStore(std::string uri) : uri_(std::move(uri)) {
  const auto options = ParseRedisUri(uri_);
  redis_ = std::make_unique<RedisClient>(options);
}

void RedisTokenStore::PutToken(const TokenRecord& record) {
  try {
    const auto key = TokenKey(record.token_hash);
    std::unordered_map<std::string, std::string> fields;
    fields.emplace("user_uuid", record.user_uuid);
    const auto expires_at =
        std::chrono::duration_cast<std::chrono::seconds>(
            record.expires_at.time_since_epoch())
            .count();
    fields.emplace("expires_at", std::to_string(expires_at));
    fields.emplace("is_revoked", record.is_revoked ? "1" : "0");
    redis_->redis.hset(key, fields.begin(), fields.end());
    redis_->redis.sadd(UserTokensKey(record.user_uuid), record.token_hash);
    const auto now = std::chrono::system_clock::now();
    if (record.expires_at > now) {
      const auto ttl = std::chrono::duration_cast<std::chrono::seconds>(
          record.expires_at - now);
      redis_->redis.expire(key, ttl);
      redis_->redis.expire(UserTokensKey(record.user_uuid), ttl);
    }
  } catch (const sw::redis::Error& ex) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable, ex.what());
  }
}

std::optional<TokenRecord> RedisTokenStore::GetToken(
    const std::string& token_hash) {
  try {
    std::unordered_map<std::string, std::string> fields;
    redis_->redis.hgetall(TokenKey(token_hash),
                          std::inserter(fields, fields.begin()));
    if (fields.empty()) {
      return std::nullopt;
    }
    TokenRecord record;
    record.token_hash = token_hash;
    record.user_uuid = fields["user_uuid"];
    const auto expires_at = std::stoll(fields["expires_at"]);
    record.expires_at =
        std::chrono::system_clock::time_point(std::chrono::seconds(expires_at));
    record.is_revoked = fields["is_revoked"] == "1";
    return record;
  } catch (const sw::redis::Error& ex) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable, ex.what());
  }
}

void RedisTokenStore::RevokeUser(const std::string& user_uuid) {
  try {
    std::unordered_set<std::string> tokens;
    redis_->redis.smembers(UserTokensKey(user_uuid),
                           std::inserter(tokens, tokens.begin()));
    for (const auto& token_hash : tokens) {
      redis_->redis.hset(TokenKey(token_hash), "is_revoked", "1");
    }
  } catch (const sw::redis::Error& ex) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable, ex.what());
  }
}
#else
RedisTokenStore::RedisTokenStore(std::string uri) : uri_(std::move(uri)) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}

void RedisTokenStore::PutToken(const TokenRecord& /*record*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}

std::optional<TokenRecord> RedisTokenStore::GetToken(
    const std::string& /*token_hash*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}

void RedisTokenStore::RevokeUser(const std::string& /*user_uuid*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}
#endif

}  // namespace veritas::gatekeeper
