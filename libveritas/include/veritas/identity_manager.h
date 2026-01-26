#pragma once

#include <chrono>
#include <functional>
#include <string>

typedef struct ssl_ctx_st SSL_CTX;

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
using LogHandler = std::function<void(LogLevel, const std::string&)>;
using RotationCallback = std::function<void()>;
using SecurityAlertCallback = std::function<void(AlertType)>;

class IdentityManager {
 public:
  explicit IdentityManager(CredentialProvider credential_provider);

  SecurityContext get_quic_context();

  AuthResult Authenticate(const GatekeeperClientConfig& config,
                          const std::string& username,
                          const std::string& password);
  AuthResult Authenticate(const GatekeeperClientConfig& config,
                          const std::string& username);

  void on_rotation(RotationCallback callback);
  void on_security_alert(SecurityAlertCallback callback);
  void set_log_handler(LogHandler handler);

 private:
  CredentialProvider credential_provider_;
  RotationCallback rotation_callback_;
  SecurityAlertCallback security_alert_callback_;
  LogHandler log_handler_;
};

using Manager = IdentityManager;

}  // namespace veritas

namespace libidentity = veritas;
