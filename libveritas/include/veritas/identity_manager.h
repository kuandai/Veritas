#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;

#include "veritas/auth/entropy.h"
#include "veritas/storage/token_store.h"

namespace veritas {

enum class AlertType {
  TokenRevoked,
  RotationFailure,
  AuthServerUnreachable,
  RepeatedAuthFailures,
  PersistentRotationFailure,
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
  AuthServerUnavailable,
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
  std::shared_ptr<SSL_CTX> handle;
  SSL_CTX* ctx = nullptr;
};

struct AuthResult {
  std::string user_uuid;
  std::string refresh_token;
  std::chrono::system_clock::time_point issued_at;
  std::chrono::system_clock::time_point expires_at;
};

struct GatekeeperClientConfig {
  std::string target;
  std::string root_cert_pem;
  bool allow_insecure = false;
};

struct RotationPolicy {
  double refresh_ratio = 0.70;
  std::chrono::milliseconds minimum_interval{250};
  std::chrono::milliseconds retry_initial{200};
  std::chrono::milliseconds retry_max{5000};
  double jitter_ratio = 0.20;
  int max_retries = 5;
  std::chrono::seconds lkg_grace_period{60};
};

struct TransportContextConfig {
  std::string certificate_chain_pem;
  std::string private_key_pem;
  std::string alpn;
};

struct RevocationPolicy {
  std::chrono::milliseconds poll_interval{5000};
  std::chrono::seconds lock_deadline{60};
};

class RotationCredentialProvider {
 public:
  virtual ~RotationCredentialProvider() = default;
  virtual std::string GetCredential() = 0;
};

class StaticRotationCredentialProvider final : public RotationCredentialProvider {
 public:
  explicit StaticRotationCredentialProvider(std::string credential)
      : credential_(std::move(credential)) {}

  std::string GetCredential() override { return credential_; }

 private:
  std::string credential_;
};

enum class AnalyticsEventType {
  AuthSuccess,
  AuthFailure,
  RotationSuccess,
  RotationFailure,
  RevocationDetected,
};

struct AnalyticsEvent {
  AnalyticsEventType type = AnalyticsEventType::AuthFailure;
  int count = 0;
  std::string detail;
};

using CredentialProvider = std::function<std::string()>;
using EntropyChecker = std::function<auth::EntropyCheckResult()>;
using AuthRunner = std::function<AuthResult(const GatekeeperClientConfig&,
                                            const std::string&,
                                            const std::string&)>;
using LogHandler = std::function<void(LogLevel, const std::string&)>;
using RotationCallback = std::function<void()>;
using SecurityAlertCallback = std::function<void(AlertType)>;
using AnalyticsCallback = std::function<void(const AnalyticsEvent&)>;

class IdentityManager {
 public:
  explicit IdentityManager(
      CredentialProvider credential_provider,
      std::optional<storage::TokenStoreConfig> token_store_config =
          std::nullopt,
      EntropyChecker entropy_checker = auth::CheckEntropyReady,
      AuthRunner auth_runner = {});

  ~IdentityManager();

  SecurityContext get_quic_context();
  void UpdateSecurityContext(const TransportContextConfig& config);

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

  void SetRotationCredentialProvider(
      std::shared_ptr<RotationCredentialProvider> provider);
  void StartRotation(const GatekeeperClientConfig& config,
                     const std::string& username,
                     RotationPolicy policy = RotationPolicy{});
  void StopRotation();
  bool IsRotationRunning() const;

  void StartRevocationMonitor(const GatekeeperClientConfig& config,
                              RevocationPolicy policy = RevocationPolicy{});
  void StopRevocationMonitor();
  bool IsRevocationMonitorRunning() const;

  static std::chrono::system_clock::time_point ComputeRotationDeadline(
      const AuthResult& identity,
      double refresh_ratio,
      std::chrono::system_clock::time_point now);
  static std::chrono::milliseconds ComputeBackoffDelay(
      int attempt,
      std::chrono::milliseconds initial,
      std::chrono::milliseconds max,
      double jitter_ratio,
      double jitter_sample);

  void on_rotation(RotationCallback callback);
  void on_security_alert(SecurityAlertCallback callback);
  void on_analytics(AnalyticsCallback callback);
  void set_log_handler(LogHandler handler);

 private:
  void RotationLoop(std::stop_token stop_token);
  void RevocationLoop(std::stop_token stop_token);
  bool SleepWithStop(std::stop_token stop_token, std::chrono::milliseconds wait);
  AuthResult RunAuthFlow(const GatekeeperClientConfig& config,
                         const std::string& username,
                         const std::string& password);
  void EmitAlert(AlertType alert);
  void EmitAnalytics(AnalyticsEventType type, int count, const std::string& detail);

  bool CanTransition(IdentityState from, IdentityState to) const;
  void TransitionTo(IdentityState next);
  void SetLastError(IdentityErrorCode error);

  CredentialProvider credential_provider_;
  EntropyChecker entropy_checker_;
  AuthRunner auth_runner_;
  RotationCallback rotation_callback_;
  SecurityAlertCallback security_alert_callback_;
  AnalyticsCallback analytics_callback_;
  LogHandler log_handler_;
  std::unique_ptr<storage::TokenStore> token_store_;
  mutable std::shared_mutex state_mutex_;
  mutable std::shared_mutex context_mutex_;
  std::shared_ptr<SSL_CTX> security_context_;
  IdentityState state_ = IdentityState::Unauthenticated;
  IdentityErrorCode last_error_ = IdentityErrorCode::None;
  std::optional<AuthResult> persisted_identity_;
  std::atomic<int> consecutive_auth_failures_{0};

  std::mutex rotation_mutex_;
  std::jthread rotation_worker_;
  std::atomic<bool> rotation_running_{false};
  GatekeeperClientConfig rotation_config_;
  std::string rotation_username_;
  RotationPolicy rotation_policy_{};
  std::shared_ptr<RotationCredentialProvider> rotation_provider_;

  std::jthread revocation_worker_;
  std::atomic<bool> revocation_running_{false};
  GatekeeperClientConfig revocation_config_;
  RevocationPolicy revocation_policy_{};
};

using Manager = IdentityManager;

}  // namespace veritas

namespace libidentity = veritas;
