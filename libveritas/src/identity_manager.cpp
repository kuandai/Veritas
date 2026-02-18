#include "veritas/identity_manager.h"

#include <stdexcept>
#include <utility>

#include "auth/auth_flow.h"

namespace veritas {

namespace {

storage::StoredIdentity ToStoredIdentity(const AuthResult& result) {
  storage::StoredIdentity stored;
  stored.user_uuid = result.user_uuid;
  stored.refresh_token = result.refresh_token;
  stored.expires_at = result.expires_at;
  return stored;
}

AuthResult ToAuthResult(const storage::StoredIdentity& stored) {
  AuthResult result;
  result.user_uuid = stored.user_uuid;
  result.refresh_token = stored.refresh_token;
  result.expires_at = stored.expires_at;
  return result;
}

}  // namespace

IdentityManager::IdentityManager(
    CredentialProvider credential_provider,
    std::optional<storage::TokenStoreConfig> token_store_config)
    : credential_provider_(std::move(credential_provider)) {
  if (!token_store_config.has_value()) {
    return;
  }
  token_store_ = storage::CreateTokenStore(*token_store_config);
  const auto loaded = token_store_->Load();
  if (loaded.has_value()) {
    persisted_identity_ = ToAuthResult(*loaded);
  }
}

SecurityContext IdentityManager::get_quic_context() {
  return SecurityContext{};
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username,
                                         const std::string& password) {
  veritas::auth::AuthFlow flow(config);
  AuthResult result = flow.Authenticate(username, password);
  persisted_identity_ = result;
  if (token_store_) {
    token_store_->Save(ToStoredIdentity(result));
  }
  return result;
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username) {
  if (!credential_provider_) {
    throw std::runtime_error("Credential provider is not configured");
  }
  veritas::auth::AuthFlow flow(config);
  AuthResult result = flow.Authenticate(username, credential_provider_());
  persisted_identity_ = result;
  if (token_store_) {
    token_store_->Save(ToStoredIdentity(result));
  }
  return result;
}

std::optional<AuthResult> IdentityManager::GetPersistedIdentity() const {
  return persisted_identity_;
}

void IdentityManager::ClearPersistedIdentity() {
  persisted_identity_.reset();
  if (token_store_) {
    token_store_->Clear();
  }
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
