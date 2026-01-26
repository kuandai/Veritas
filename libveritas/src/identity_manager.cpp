#include "veritas/identity_manager.h"

#include <stdexcept>
#include <utility>

#include "auth/auth_flow.h"

namespace veritas {

IdentityManager::IdentityManager(CredentialProvider credential_provider)
    : credential_provider_(std::move(credential_provider)) {}

SecurityContext IdentityManager::get_quic_context() {
  return SecurityContext{};
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username,
                                         const std::string& password) {
  veritas::auth::AuthFlow flow(config);
  return flow.Authenticate(username, password);
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username) {
  if (!credential_provider_) {
    throw std::runtime_error("Credential provider is not configured");
  }
  veritas::auth::AuthFlow flow(config);
  return flow.Authenticate(username, credential_provider_());
}

void IdentityManager::on_rotation(RotationCallback callback) {
  rotation_callback_ = std::move(callback);
}

void IdentityManager::on_security_alert(SecurityAlertCallback callback) {
  security_alert_callback_ = std::move(callback);
}

void IdentityManager::set_log_handler(LogHandler handler) {
  log_handler_ = std::move(handler);
}

}  // namespace veritas
