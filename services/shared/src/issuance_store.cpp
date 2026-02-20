#include "veritas/shared/issuance_store.h"

#include <cstdint>
#include <mutex>
#include <unordered_map>

#if !defined(VERITAS_DISABLE_REDIS)
#include <sw/redis++/redis++.h>
#endif

namespace veritas::shared {
namespace {

int64_t ToUnixSeconds(const std::chrono::system_clock::time_point& tp) {
  return std::chrono::duration_cast<std::chrono::seconds>(
             tp.time_since_epoch())
      .count();
}

std::chrono::system_clock::time_point FromUnixSecondsString(
    const std::string& value) {
  if (value.empty()) {
    return {};
  }
  return std::chrono::system_clock::time_point(std::chrono::seconds(
      static_cast<int64_t>(std::stoll(value))));
}

std::string ToString(IssuanceState state) {
  return state == IssuanceState::Revoked ? "revoked" : "active";
}

IssuanceState ParseState(const std::string& value) {
  return value == "revoked" ? IssuanceState::Revoked : IssuanceState::Active;
}

void ValidateIssuanceRecord(const IssuanceRecord& record) {
  if (record.certificate_serial.empty()) {
    throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                           "certificate serial is required");
  }
  if (record.certificate_pem.empty()) {
    throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                           "certificate PEM is required");
  }
  if (record.user_uuid.empty()) {
    throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                           "user UUID is required");
  }
  if (record.token_hash.empty()) {
    throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                           "token hash is required");
  }
}

class InMemoryIssuanceStore final : public IssuanceStore {
 public:
  void PutIssuance(const IssuanceRecord& record) override {
    ValidateIssuanceRecord(record);
    std::lock_guard<std::mutex> lock(mutex_);

    records_by_serial_[record.certificate_serial] = record;
    serial_by_token_hash_[record.token_hash] = record.certificate_serial;
    if (!record.idempotency_key.empty()) {
      RegisterIdempotencyKeyLocked(record.idempotency_key,
                                   record.certificate_serial);
    }
  }

  std::optional<IssuanceRecord> GetBySerial(
      const std::string& certificate_serial) override {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_by_serial_.find(certificate_serial);
    if (it == records_by_serial_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  std::optional<IssuanceRecord> GetByTokenHash(
      const std::string& token_hash) override {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto token_it = serial_by_token_hash_.find(token_hash);
    if (token_it == serial_by_token_hash_.end()) {
      return std::nullopt;
    }
    const auto serial_it = records_by_serial_.find(token_it->second);
    if (serial_it == records_by_serial_.end()) {
      return std::nullopt;
    }
    return serial_it->second;
  }

  bool RegisterIdempotencyKey(const std::string& idempotency_key,
                              const std::string& certificate_serial) override {
    std::lock_guard<std::mutex> lock(mutex_);
    return RegisterIdempotencyKeyLocked(idempotency_key, certificate_serial);
  }

  std::optional<std::string> ResolveIdempotencyKey(
      const std::string& idempotency_key) override {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = serial_by_idempotency_key_.find(idempotency_key);
    if (it == serial_by_idempotency_key_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void Revoke(const std::string& certificate_serial,
              const std::string& reason,
              std::chrono::system_clock::time_point revoked_at) override {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_by_serial_.find(certificate_serial);
    if (it == records_by_serial_.end()) {
      throw SharedStoreError(SharedStoreError::Kind::NotFound,
                             "certificate serial not found");
    }
    it->second.state = IssuanceState::Revoked;
    it->second.revoke_reason = reason;
    it->second.revoked_at = revoked_at;
  }

 private:
  bool RegisterIdempotencyKeyLocked(const std::string& idempotency_key,
                                    const std::string& certificate_serial) {
    if (idempotency_key.empty()) {
      throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                             "idempotency key is required");
    }
    if (certificate_serial.empty()) {
      throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                             "certificate serial is required");
    }
    const auto it = serial_by_idempotency_key_.find(idempotency_key);
    if (it == serial_by_idempotency_key_.end()) {
      serial_by_idempotency_key_[idempotency_key] = certificate_serial;
      return true;
    }
    return it->second == certificate_serial;
  }

  std::mutex mutex_;
  std::unordered_map<std::string, IssuanceRecord> records_by_serial_;
  std::unordered_map<std::string, std::string> serial_by_token_hash_;
  std::unordered_map<std::string, std::string> serial_by_idempotency_key_;
};

#if !defined(VERITAS_DISABLE_REDIS)

std::string IssuanceKey(const std::string& serial) {
  return "shared:issuance:" + serial;
}

std::string TokenIndexKey(const std::string& token_hash) {
  return "shared:token:" + token_hash;
}

std::string IdempotencyIndexKey(const std::string& idempotency_key) {
  return "shared:idempotency:" + idempotency_key;
}

class RedisIssuanceStore final : public IssuanceStore {
 public:
  explicit RedisIssuanceStore(std::string redis_uri)
      : redis_(std::move(redis_uri)) {}

  void PutIssuance(const IssuanceRecord& record) override {
    ValidateIssuanceRecord(record);
    try {
      if (!record.idempotency_key.empty() &&
          !RegisterIdempotencyKey(record.idempotency_key,
                                  record.certificate_serial)) {
        throw SharedStoreError(SharedStoreError::Kind::Conflict,
                               "idempotency key already linked to another serial");
      }

      std::unordered_map<std::string, std::string> fields;
      fields.emplace("user_uuid", record.user_uuid);
      fields.emplace("certificate_pem", record.certificate_pem);
      fields.emplace("certificate_chain_pem", record.certificate_chain_pem);
      fields.emplace("token_hash", record.token_hash);
      fields.emplace("idempotency_key", record.idempotency_key);
      fields.emplace("issued_at", std::to_string(ToUnixSeconds(record.issued_at)));
      fields.emplace("expires_at", std::to_string(ToUnixSeconds(record.expires_at)));
      fields.emplace("state", ToString(record.state));
      fields.emplace("revoke_reason", record.revoke_reason);
      fields.emplace("revoked_at", std::to_string(ToUnixSeconds(record.revoked_at)));
      redis_.hset(IssuanceKey(record.certificate_serial), fields.begin(),
                  fields.end());
      redis_.set(TokenIndexKey(record.token_hash), record.certificate_serial);
    } catch (const SharedStoreError&) {
      throw;
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

  std::optional<IssuanceRecord> GetBySerial(
      const std::string& certificate_serial) override {
    try {
      std::unordered_map<std::string, std::string> fields;
      redis_.hgetall(IssuanceKey(certificate_serial),
                     std::inserter(fields, fields.begin()));
      if (fields.empty()) {
        return std::nullopt;
      }

      IssuanceRecord record;
      record.certificate_serial = certificate_serial;
      record.user_uuid = fields["user_uuid"];
      record.certificate_pem = fields["certificate_pem"];
      record.certificate_chain_pem = fields["certificate_chain_pem"];
      record.token_hash = fields["token_hash"];
      record.idempotency_key = fields["idempotency_key"];
      record.issued_at = FromUnixSecondsString(fields["issued_at"]);
      record.expires_at = FromUnixSecondsString(fields["expires_at"]);
      record.state = ParseState(fields["state"]);
      record.revoke_reason = fields["revoke_reason"];
      record.revoked_at = FromUnixSecondsString(fields["revoked_at"]);
      return record;
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

  std::optional<IssuanceRecord> GetByTokenHash(
      const std::string& token_hash) override {
    try {
      const auto serial = redis_.get(TokenIndexKey(token_hash));
      if (!serial.has_value()) {
        return std::nullopt;
      }
      return GetBySerial(*serial);
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

  bool RegisterIdempotencyKey(const std::string& idempotency_key,
                              const std::string& certificate_serial) override {
    if (idempotency_key.empty()) {
      throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                             "idempotency key is required");
    }
    try {
      const auto key = IdempotencyIndexKey(idempotency_key);
      const auto existing = redis_.get(key);
      if (!existing.has_value()) {
        redis_.set(key, certificate_serial);
        return true;
      }
      return *existing == certificate_serial;
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

  std::optional<std::string> ResolveIdempotencyKey(
      const std::string& idempotency_key) override {
    try {
      return redis_.get(IdempotencyIndexKey(idempotency_key));
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

  void Revoke(const std::string& certificate_serial,
              const std::string& reason,
              std::chrono::system_clock::time_point revoked_at) override {
    try {
      if (!redis_.exists(IssuanceKey(certificate_serial))) {
        throw SharedStoreError(SharedStoreError::Kind::NotFound,
                               "certificate serial not found");
      }
      redis_.hset(IssuanceKey(certificate_serial), "state", "revoked");
      redis_.hset(IssuanceKey(certificate_serial), "revoke_reason", reason);
      redis_.hset(IssuanceKey(certificate_serial), "revoked_at",
                  std::to_string(ToUnixSeconds(revoked_at)));
    } catch (const SharedStoreError&) {
      throw;
    } catch (const sw::redis::Error& ex) {
      throw SharedStoreError(SharedStoreError::Kind::Unavailable, ex.what());
    }
  }

 private:
  sw::redis::Redis redis_;
};

#else

class RedisIssuanceStore final : public IssuanceStore {
 public:
  explicit RedisIssuanceStore(std::string /*redis_uri*/) {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }

  void PutIssuance(const IssuanceRecord& /*record*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
  std::optional<IssuanceRecord> GetBySerial(
      const std::string& /*certificate_serial*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
  std::optional<IssuanceRecord> GetByTokenHash(
      const std::string& /*token_hash*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
  bool RegisterIdempotencyKey(const std::string& /*idempotency_key*/,
                              const std::string& /*certificate_serial*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
  std::optional<std::string> ResolveIdempotencyKey(
      const std::string& /*idempotency_key*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
  void Revoke(const std::string& /*certificate_serial*/,
              const std::string& /*reason*/,
              std::chrono::system_clock::time_point /*revoked_at*/) override {
    throw SharedStoreError(SharedStoreError::Kind::Unavailable,
                           "Redis support is disabled");
  }
};

#endif

}  // namespace

SharedStoreError::SharedStoreError(Kind kind, const std::string& message)
    : std::runtime_error(message), kind_(kind) {}

SharedStoreError::Kind SharedStoreError::kind() const noexcept { return kind_; }

std::shared_ptr<IssuanceStore> CreateIssuanceStore(
    const SharedStoreConfig& config) {
  switch (config.backend) {
    case SharedStoreBackend::InMemory:
      return std::make_shared<InMemoryIssuanceStore>();
    case SharedStoreBackend::Redis:
      if (config.redis_uri.empty()) {
        throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                               "redis URI is required");
      }
      return std::make_shared<RedisIssuanceStore>(config.redis_uri);
    default:
      throw SharedStoreError(SharedStoreError::Kind::InvalidArgument,
                             "unsupported backend");
  }
}

}  // namespace veritas::shared
