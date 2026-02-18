#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>

typedef struct ssl_ctx_st SSL_CTX;

#include "veritas/auth/entropy.h"
#include "veritas/storage/token_store.h"

namespace veritas {

enum class AlertType {
  TokenRevoked,
  RotationFailure,
  Unknown,
};

enum class LogLevel {
  Debug,
  Info,
  Warn,
  Error,
  Critical,
};

enum class IdentityState {
  Unauthenticated,
  Ready,
  Locked,
};

enum class IdentityErrorCode {
  None,
  MissingCredentialProvider,
  InvalidStateTransition,
  AuthenticationFailed,
  PersistenceFailure,
  EntropyUnavailable,
};

class IdentityManagerError : public std::runtime_error {
 public:
  IdentityManagerError(IdentityErrorCode code, const std::string& message)
      : std::runtime_error(message), code_(code) {}

  IdentityErrorCode code() const noexcept { return code_; }

 private:
  IdentityErrorCode code_;
};

struct SecurityContext {
  SSL_CTX* ctx = nullptr;
};

struct AuthResult {
  std::string user_uuid;
  std::string refresh_token;
  std::chrono::system_clock::time_point expires_at;
};

struct GatekeeperClientConfig {
  std::string target;
  std::string root_cert_pem;
  bool allow_insecure = false;
};

using CredentialProvider = std::function<std::string()>;
using EntropyChecker = std::function<auth::EntropyCheckResult()>;
using LogHandler = std::function<void(LogLevel, const std::string&)>;
using RotationCallback = std::function<void()>;
using SecurityAlertCallback = std::function<void(AlertType)>;

class IdentityManager {
 public:
  explicit IdentityManager(
      CredentialProvider credential_provider,
      std::optional<storage::TokenStoreConfig> token_store_config =
          std::nullopt,
      EntropyChecker entropy_checker = auth::CheckEntropyReady);

  SecurityContext get_quic_context();

  AuthResult Authenticate(const GatekeeperClientConfig& config,
                          const std::string& username,
                          const std::string& password);
  AuthResult Authenticate(const GatekeeperClientConfig& config,
                          const std::string& username);
  IdentityState GetState() const;
  IdentityErrorCode GetLastError() const;
  std::optional<AuthResult> GetPersistedIdentity() const;
  void ClearPersistedIdentity();
  void Lock();

  void on_rotation(RotationCallback callback);
  void on_security_alert(SecurityAlertCallback callback);
  void set_log_handler(LogHandler handler);

 private:
  bool CanTransition(IdentityState from, IdentityState to) const;
  void TransitionTo(IdentityState next);
  void SetLastError(IdentityErrorCode error);

  CredentialProvider credential_provider_;
  EntropyChecker entropy_checker_;
  RotationCallback rotation_callback_;
  SecurityAlertCallback security_alert_callback_;
  LogHandler log_handler_;
  std::unique_ptr<storage::TokenStore> token_store_;
  mutable std::shared_mutex state_mutex_;
  IdentityState state_ = IdentityState::Unauthenticated;
  IdentityErrorCode last_error_ = IdentityErrorCode::None;
  std::optional<AuthResult> persisted_identity_;
};

using Manager = IdentityManager;

}  // namespace veritas

namespace libidentity = veritas;
