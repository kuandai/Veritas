#include "veritas/shared/token_store.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace veritas::shared {

namespace {

std::string ToLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

bool ParseBoolQuery(std::string value, bool* parsed) {
  value = ToLower(std::move(value));
  if (value == "1" || value == "true" || value == "yes") {
    *parsed = true;
    return true;
  }
  if (value == "0" || value == "false" || value == "no") {
    *parsed = false;
    return true;
  }
  return false;
}

int ParseIntValue(std::string_view value, std::string_view field_name) {
  if (value.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          std::string(field_name) + " is empty");
  }
  long long parsed = 0;
  std::size_t consumed = 0;
  try {
    parsed = std::stoll(std::string(value), &consumed, 10);
  } catch (const std::exception&) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          std::string(field_name) + " is invalid");
  }
  if (consumed != value.size() || parsed < std::numeric_limits<int>::min() ||
      parsed > std::numeric_limits<int>::max()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          std::string(field_name) + " is out of range");
  }
  return static_cast<int>(parsed);
}

std::unordered_map<std::string, std::string> ParseQuery(
    std::string_view query) {
  std::unordered_map<std::string, std::string> parsed;
  std::size_t start = 0;
  while (start <= query.size()) {
    const std::size_t end = query.find('&', start);
    const std::string_view part =
        query.substr(start, end == std::string_view::npos ? std::string_view::npos
                                                           : end - start);
    if (!part.empty()) {
      const std::size_t eq = part.find('=');
      const std::string key = std::string(part.substr(0, eq));
      const std::string value =
          eq == std::string_view::npos ? "" : std::string(part.substr(eq + 1));
      if (key.empty()) {
        throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                              "Redis URI query contains an empty key");
      }
      parsed[key] = value;
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
  return parsed;
}

void ParseAuthority(std::string_view authority,
                    RedisConnectionConfig* config) {
  if (authority.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis URI authority is empty");
  }

  std::string_view hostport = authority;
  const std::size_t at_pos = authority.rfind('@');
  if (at_pos != std::string_view::npos) {
    const std::string_view credentials = authority.substr(0, at_pos);
    hostport = authority.substr(at_pos + 1);
    const std::size_t colon = credentials.find(':');
    if (colon == std::string_view::npos) {
      // Keep compatibility with legacy `password@host` parsing.
      config->password = std::string(credentials);
    } else {
      config->username = std::string(credentials.substr(0, colon));
      config->password = std::string(credentials.substr(colon + 1));
    }
  }

  if (hostport.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis host is empty");
  }

  if (hostport.front() == '[') {
    const std::size_t close_bracket = hostport.find(']');
    if (close_bracket == std::string_view::npos) {
      throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                            "Redis IPv6 host is malformed");
    }
    config->host = std::string(hostport.substr(1, close_bracket - 1));
    const std::string_view rest = hostport.substr(close_bracket + 1);
    if (!rest.empty()) {
      if (rest.front() != ':' || rest.size() == 1) {
        throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                              "Redis port is malformed");
      }
      config->port = ParseIntValue(rest.substr(1), "Redis port");
    }
  } else {
    const std::size_t colon = hostport.rfind(':');
    if (colon == std::string_view::npos) {
      config->host = std::string(hostport);
    } else {
      config->host = std::string(hostport.substr(0, colon));
      config->port = ParseIntValue(hostport.substr(colon + 1), "Redis port");
    }
  }

  if (config->host.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis host is empty");
  }
  if (config->port <= 0 || config->port > 65535) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis port must be in range 1-65535");
  }
}

void ValidateTlsConfig(const RedisConnectionConfig& config) {
  if (!config.use_tls) {
    if (!config.tls_ca_cert_path.empty() || !config.tls_ca_cert_dir.empty() ||
        !config.tls_cert_path.empty() || !config.tls_key_path.empty() ||
        !config.tls_sni.empty() || !config.tls_verify_peer) {
      throw TokenStoreError(
          TokenStoreError::Kind::Unavailable,
          "TLS options require rediss://");
    }
    return;
  }

  if (config.tls_verify_peer && config.tls_ca_cert_path.empty() &&
      config.tls_ca_cert_dir.empty()) {
    throw TokenStoreError(
        TokenStoreError::Kind::Unavailable,
        "rediss:// requires cacert or cacertdir when verify_peer is enabled");
  }
  if (config.tls_cert_path.empty() != config.tls_key_path.empty()) {
    throw TokenStoreError(
        TokenStoreError::Kind::Unavailable,
        "Redis TLS client auth requires both cert and key");
  }
}

}  // namespace

RedisConnectionConfig ParseRedisConnectionConfig(const std::string& uri) {
  if (uri.empty()) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis URI is empty");
  }

  const std::size_t scheme_pos = uri.find("://");
  if (scheme_pos == std::string::npos) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis URI must include a scheme");
  }
  const std::string scheme = ToLower(uri.substr(0, scheme_pos));
  RedisConnectionConfig config;
  if (scheme == "redis") {
    config.use_tls = false;
  } else if (scheme == "rediss") {
    config.use_tls = true;
  } else {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "Redis URI scheme must be redis:// or rediss://");
  }

  std::string_view working(uri);
  working.remove_prefix(scheme_pos + 3);
  std::string_view query;
  const std::size_t query_pos = working.find('?');
  if (query_pos != std::string_view::npos) {
    query = working.substr(query_pos + 1);
    working = working.substr(0, query_pos);
  }

  std::string_view authority = working;
  const std::size_t slash_pos = working.find('/');
  if (slash_pos != std::string_view::npos) {
    authority = working.substr(0, slash_pos);
    const std::string_view db_value = working.substr(slash_pos + 1);
    if (!db_value.empty()) {
      config.db = ParseIntValue(db_value, "Redis db");
      if (config.db < 0) {
        throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                              "Redis db must be non-negative");
      }
    }
  }

  ParseAuthority(authority, &config);
  const auto params = ParseQuery(query);
  for (const auto& [key, value] : params) {
    if (key == "cacert") {
      config.tls_ca_cert_path = value;
    } else if (key == "cacertdir") {
      config.tls_ca_cert_dir = value;
    } else if (key == "cert") {
      config.tls_cert_path = value;
    } else if (key == "key") {
      config.tls_key_path = value;
    } else if (key == "sni") {
      config.tls_sni = value;
    } else if (key == "verify_peer") {
      if (!ParseBoolQuery(value, &config.tls_verify_peer)) {
        throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                              "Redis URI verify_peer must be boolean");
      }
    } else {
      throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                            "Unsupported Redis URI query parameter: " + key);
    }
  }
  ValidateTlsConfig(config);
  return config;
}

namespace {

#if !defined(VERITAS_DISABLE_REDIS)
sw::redis::ConnectionOptions BuildRedisOptions(const RedisConnectionConfig& parsed) {
  sw::redis::ConnectionOptions options;
  options.host = parsed.host;
  options.port = parsed.port;
  options.db = parsed.db;
  if (!parsed.username.empty()) {
    options.user = parsed.username;
  }
  if (!parsed.password.empty()) {
    options.password = parsed.password;
  }
  options.connect_timeout = std::chrono::milliseconds(200);
  options.socket_timeout = std::chrono::milliseconds(200);
  if (parsed.use_tls) {
#if defined(SEWENEW_REDISPLUSPLUS_NO_TLS_H)
    throw TokenStoreError(
        TokenStoreError::Kind::Unavailable,
        "Redis client library was built without TLS support");
#else
    options.tls.enabled = true;
    options.tls.cacert = parsed.tls_ca_cert_path;
    options.tls.cacertdir = parsed.tls_ca_cert_dir;
    options.tls.cert = parsed.tls_cert_path;
    options.tls.key = parsed.tls_key_path;
    options.tls.sni = parsed.tls_sni.empty() ? parsed.host : parsed.tls_sni;
#if defined(REDIS_PLUS_PLUS_TLS_VERIFY_MODE)
    options.tls.verify_mode = parsed.tls_verify_peer
                                  ? REDIS_SSL_VERIFY_PEER
                                  : REDIS_SSL_VERIFY_NONE;
#else
    if (!parsed.tls_verify_peer) {
      throw TokenStoreError(
          TokenStoreError::Kind::Unavailable,
          "Redis TLS verify mode override is unsupported in this build");
    }
#endif
#endif
  }
  return options;
}
#endif

std::string TokenKey(const std::string& token_hash) {
  return "token:" + token_hash;
}

std::string UserTokensKey(const std::string& user_uuid) {
  return "user_tokens:" + user_uuid;
}

std::string TombstoneKey(const std::string& token_hash) {
  return "token_tombstone:" + token_hash;
}

}  // namespace

TokenStoreError::TokenStoreError(Kind kind, const std::string& message)
    : std::runtime_error(message), kind_(kind) {}

void InMemoryTokenStore::CleanupExpiredLocked() {
  const auto now = std::chrono::system_clock::now();
  for (auto it = tombstones_.begin(); it != tombstones_.end();) {
    if (it->second.expires_at <= now) {
      it = tombstones_.erase(it);
    } else {
      ++it;
    }
  }
}

void InMemoryTokenStore::PutToken(const TokenRecord& record) {
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupExpiredLocked();
  const auto tombstone_it = tombstones_.find(record.token_hash);
  if (tombstone_it != tombstones_.end()) {
    throw TokenStoreError(TokenStoreError::Kind::ReplayRejected,
                          "token hash is tombstoned");
  }
  tokens_[record.token_hash] = record;
}

std::optional<TokenRecord> InMemoryTokenStore::GetToken(
    const std::string& token_hash) {
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupExpiredLocked();
  auto it = tokens_.find(token_hash);
  if (it == tokens_.end()) {
    return std::nullopt;
  }
  return it->second;
}

TokenStatus InMemoryTokenStore::GetTokenStatus(const std::string& token_hash) {
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupExpiredLocked();

  const auto token_it = tokens_.find(token_hash);
  if (token_it != tokens_.end()) {
    TokenStatus status;
    status.user_uuid = token_it->second.user_uuid;
    if (token_it->second.is_revoked) {
      status.state = TokenState::Revoked;
      status.reason = token_it->second.revoke_reason;
      status.revoked_at = token_it->second.revoked_at;
    } else {
      status.state = TokenState::Active;
    }
    return status;
  }

  const auto tombstone_it = tombstones_.find(token_hash);
  if (tombstone_it != tombstones_.end()) {
    TokenStatus status;
    status.state = TokenState::Revoked;
    status.user_uuid = tombstone_it->second.user_uuid;
    status.reason = tombstone_it->second.reason;
    status.revoked_at = tombstone_it->second.revoked_at;
    return status;
  }

  return TokenStatus{};
}

void InMemoryTokenStore::RevokeToken(const std::string& token_hash,
                                     const std::string& reason) {
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupExpiredLocked();
  const auto now = std::chrono::system_clock::now();
  const std::string effective_reason =
      reason.empty() ? "revoked" : reason;

  auto token_it = tokens_.find(token_hash);
  TombstoneRecord tombstone;
  tombstone.reason = effective_reason;
  tombstone.revoked_at = now;
  tombstone.expires_at = now + tombstone_ttl_;
  if (token_it != tokens_.end()) {
    token_it->second.is_revoked = true;
    token_it->second.revoke_reason = effective_reason;
    token_it->second.revoked_at = now;
    tombstone.user_uuid = token_it->second.user_uuid;
  }
  tombstones_[token_hash] = tombstone;
}

void InMemoryTokenStore::RevokeUser(const std::string& user_uuid) {
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupExpiredLocked();
  const auto now = std::chrono::system_clock::now();
  for (auto& entry : tokens_) {
    if (entry.second.user_uuid == user_uuid) {
      entry.second.is_revoked = true;
      entry.second.revoke_reason = "user-revoked";
      entry.second.revoked_at = now;
      tombstones_[entry.first] = TombstoneRecord{
          user_uuid, "user-revoked", now, now + tombstone_ttl_};
    }
  }
}

#if !defined(VERITAS_DISABLE_REDIS)
RedisTokenStore::RedisTokenStore(std::string uri) : uri_(std::move(uri)) {
  const auto parsed = ParseRedisConnectionConfig(uri_);
  const auto options = BuildRedisOptions(parsed);
  redis_ = std::make_unique<RedisClient>(options);
}

void RedisTokenStore::PutToken(const TokenRecord& record) {
  try {
    if (redis_->redis.exists(TombstoneKey(record.token_hash))) {
      throw TokenStoreError(TokenStoreError::Kind::ReplayRejected,
                            "token hash is tombstoned");
    }
    const auto key = TokenKey(record.token_hash);
    std::unordered_map<std::string, std::string> fields;
    fields.emplace("user_uuid", record.user_uuid);
    const auto expires_at =
        std::chrono::duration_cast<std::chrono::seconds>(
            record.expires_at.time_since_epoch())
            .count();
    fields.emplace("expires_at", std::to_string(expires_at));
    fields.emplace("is_revoked", record.is_revoked ? "1" : "0");
    fields.emplace("revoke_reason", record.revoke_reason);
    const auto revoked_at =
        std::chrono::duration_cast<std::chrono::seconds>(
            record.revoked_at.time_since_epoch())
            .count();
    fields.emplace("revoked_at", std::to_string(revoked_at));
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
    const auto revoked_it = fields.find("revoked_at");
    const auto revoked_at =
        revoked_it == fields.end() || revoked_it->second.empty()
            ? 0
            : std::stoll(revoked_it->second);
    record.revoked_at =
        std::chrono::system_clock::time_point(std::chrono::seconds(revoked_at));
    const auto reason_it = fields.find("revoke_reason");
    if (reason_it != fields.end()) {
      record.revoke_reason = reason_it->second;
    }
    return record;
  } catch (const sw::redis::Error& ex) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable, ex.what());
  }
}

TokenStatus RedisTokenStore::GetTokenStatus(const std::string& token_hash) {
  try {
    TokenStatus status;
    std::unordered_map<std::string, std::string> fields;
    redis_->redis.hgetall(TokenKey(token_hash),
                          std::inserter(fields, fields.begin()));
    if (!fields.empty()) {
      status.user_uuid = fields["user_uuid"];
      if (fields["is_revoked"] == "1") {
        status.state = TokenState::Revoked;
        const auto reason_it = fields.find("revoke_reason");
        if (reason_it != fields.end()) {
          status.reason = reason_it->second;
        }
        const auto revoked_it = fields.find("revoked_at");
        const auto revoked_at =
            revoked_it == fields.end() || revoked_it->second.empty()
                ? 0
                : std::stoll(revoked_it->second);
        status.revoked_at = std::chrono::system_clock::time_point(
            std::chrono::seconds(revoked_at));
      } else {
        status.state = TokenState::Active;
      }
      return status;
    }

    const auto tombstone = redis_->redis.get(TombstoneKey(token_hash));
    if (tombstone.has_value()) {
      status.state = TokenState::Revoked;
      status.reason = *tombstone;
      status.revoked_at = std::chrono::system_clock::now();
      return status;
    }
    return status;
  } catch (const TokenStoreError&) {
    throw;
  } catch (const sw::redis::Error& ex) {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable, ex.what());
  }
}

void RedisTokenStore::RevokeToken(const std::string& token_hash,
                                  const std::string& reason) {
  try {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             now.time_since_epoch())
                             .count();
    const std::string effective_reason =
        reason.empty() ? "revoked" : reason;
    redis_->redis.hset(TokenKey(token_hash), "is_revoked", "1");
    redis_->redis.hset(TokenKey(token_hash), "revoke_reason", effective_reason);
    redis_->redis.hset(TokenKey(token_hash), "revoked_at", std::to_string(seconds));
    redis_->redis.setex(TombstoneKey(token_hash), std::chrono::hours(24),
                        effective_reason);
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
      RevokeToken(token_hash, "user-revoked");
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

TokenStatus RedisTokenStore::GetTokenStatus(const std::string& /*token_hash*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}

void RedisTokenStore::RevokeToken(const std::string& /*token_hash*/,
                                  const std::string& /*reason*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}

void RedisTokenStore::RevokeUser(const std::string& /*user_uuid*/) {
  throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                        "Redis support is disabled");
}
#endif

}  // namespace veritas::shared
