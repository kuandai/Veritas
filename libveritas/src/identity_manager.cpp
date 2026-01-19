#include "veritas/identity_manager.h"

#include <utility>

namespace veritas {

IdentityManager::IdentityManager(CredentialProvider credential_provider)
    : credential_provider_(std::move(credential_provider)) {}

SecurityContext IdentityManager::get_quic_context() {
  return SecurityContext{};
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
