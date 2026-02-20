#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace veritas::shared {

enum class SharedStoreBackend {
  InMemory,
  Redis,
};

struct SharedStoreConfig {
  SharedStoreBackend backend = SharedStoreBackend::InMemory;
  std::string redis_uri;
};

enum class IssuanceState {
  Active,
  Revoked,
};

struct IssuanceRecord {
  std::string certificate_serial;
  std::string user_uuid;
  std::string token_hash;
  std::string idempotency_key;
  std::chrono::system_clock::time_point issued_at{};
  std::chrono::system_clock::time_point expires_at{};
  IssuanceState state = IssuanceState::Active;
  std::string revoke_reason;
  std::chrono::system_clock::time_point revoked_at{};
};

class SharedStoreError : public std::runtime_error {
 public:
  enum class Kind {
    InvalidArgument,
    Conflict,
    NotFound,
    Unavailable,
  };

  SharedStoreError(Kind kind, const std::string& message);

  Kind kind() const noexcept;

 private:
  Kind kind_;
};

class IssuanceStore {
 public:
  virtual ~IssuanceStore() = default;

  virtual void PutIssuance(const IssuanceRecord& record) = 0;
  virtual std::optional<IssuanceRecord> GetBySerial(
      const std::string& certificate_serial) = 0;
  virtual std::optional<IssuanceRecord> GetByTokenHash(
      const std::string& token_hash) = 0;
  virtual bool RegisterIdempotencyKey(const std::string& idempotency_key,
                                      const std::string& certificate_serial) = 0;
  virtual std::optional<std::string> ResolveIdempotencyKey(
      const std::string& idempotency_key) = 0;
  virtual void Revoke(const std::string& certificate_serial,
                      const std::string& reason,
                      std::chrono::system_clock::time_point revoked_at) = 0;
};

std::shared_ptr<IssuanceStore> CreateIssuanceStore(const SharedStoreConfig& config);

}  // namespace veritas::shared
