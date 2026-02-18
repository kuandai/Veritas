#include "veritas/identity_manager.h"

#include <mutex>
#include <shared_mutex>
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
    std::optional<storage::TokenStoreConfig> token_store_config,
    EntropyChecker entropy_checker)
    : credential_provider_(std::move(credential_provider)),
      entropy_checker_(std::move(entropy_checker)) {
  if (!token_store_config.has_value()) {
    return;
  }
  token_store_ = storage::CreateTokenStore(*token_store_config);
  const auto loaded = token_store_->Load();
  if (loaded.has_value()) {
    {
      std::unique_lock lock(state_mutex_);
      persisted_identity_ = ToAuthResult(*loaded);
    }
    TransitionTo(IdentityState::Ready);
  }
}

SecurityContext IdentityManager::get_quic_context() {
  return SecurityContext{};
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username,
                                         const std::string& password) {
  const auth::EntropyCheckResult entropy =
      entropy_checker_ ? entropy_checker_() : auth::CheckEntropyReady();
  if (entropy.status != auth::EntropyStatus::Ready) {
    SetLastError(IdentityErrorCode::EntropyUnavailable);
    throw IdentityManagerError(
        IdentityErrorCode::EntropyUnavailable,
        entropy.message.empty()
            ? "entropy preflight did not report readiness"
            : entropy.message);
  }
  if (GetState() == IdentityState::Locked) {
    SetLastError(IdentityErrorCode::InvalidStateTransition);
    throw IdentityManagerError(IdentityErrorCode::InvalidStateTransition,
                               "Identity is locked");
  }
  veritas::auth::AuthFlow flow(config);
  try {
    AuthResult result = flow.Authenticate(username, password);
    {
      std::unique_lock lock(state_mutex_);
      persisted_identity_ = result;
    }
    if (token_store_) {
      token_store_->Save(ToStoredIdentity(result));
    }
    TransitionTo(IdentityState::Ready);
    SetLastError(IdentityErrorCode::None);
    return result;
  } catch (const storage::TokenStoreError&) {
    SetLastError(IdentityErrorCode::PersistenceFailure);
    throw;
  } catch (const std::exception& ex) {
    SetLastError(IdentityErrorCode::AuthenticationFailed);
    throw IdentityManagerError(IdentityErrorCode::AuthenticationFailed,
                               ex.what());
  }
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username) {
  const auth::EntropyCheckResult entropy =
      entropy_checker_ ? entropy_checker_() : auth::CheckEntropyReady();
  if (entropy.status != auth::EntropyStatus::Ready) {
    SetLastError(IdentityErrorCode::EntropyUnavailable);
    throw IdentityManagerError(
        IdentityErrorCode::EntropyUnavailable,
        entropy.message.empty()
            ? "entropy preflight did not report readiness"
            : entropy.message);
  }
  if (!credential_provider_) {
    SetLastError(IdentityErrorCode::MissingCredentialProvider);
    throw IdentityManagerError(IdentityErrorCode::MissingCredentialProvider,
                               "Credential provider is not configured");
  }
  veritas::auth::AuthFlow flow(config);
  if (GetState() == IdentityState::Locked) {
    SetLastError(IdentityErrorCode::InvalidStateTransition);
    throw IdentityManagerError(IdentityErrorCode::InvalidStateTransition,
                               "Identity is locked");
  }
  try {
    AuthResult result = flow.Authenticate(username, credential_provider_());
    {
      std::unique_lock lock(state_mutex_);
      persisted_identity_ = result;
    }
    if (token_store_) {
      token_store_->Save(ToStoredIdentity(result));
    }
    TransitionTo(IdentityState::Ready);
    SetLastError(IdentityErrorCode::None);
    return result;
  } catch (const storage::TokenStoreError&) {
    SetLastError(IdentityErrorCode::PersistenceFailure);
    throw;
  } catch (const std::exception& ex) {
    SetLastError(IdentityErrorCode::AuthenticationFailed);
    throw IdentityManagerError(IdentityErrorCode::AuthenticationFailed,
                               ex.what());
  }
}

IdentityState IdentityManager::GetState() const {
  std::shared_lock lock(state_mutex_);
  return state_;
}

IdentityErrorCode IdentityManager::GetLastError() const {
  std::shared_lock lock(state_mutex_);
  return last_error_;
}

std::optional<AuthResult> IdentityManager::GetPersistedIdentity() const {
  std::shared_lock lock(state_mutex_);
  return persisted_identity_;
}

void IdentityManager::ClearPersistedIdentity() {
  try {
    if (token_store_) {
      token_store_->Clear();
    }
    {
      std::unique_lock lock(state_mutex_);
      persisted_identity_.reset();
    }
    TransitionTo(IdentityState::Unauthenticated);
    SetLastError(IdentityErrorCode::None);
  } catch (const storage::TokenStoreError&) {
    SetLastError(IdentityErrorCode::PersistenceFailure);
    throw;
  }
}

void IdentityManager::Lock() {
  TransitionTo(IdentityState::Locked);
  SetLastError(IdentityErrorCode::None);
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

bool IdentityManager::CanTransition(IdentityState from, IdentityState to) const {
  switch (from) {
    case IdentityState::Unauthenticated:
      return to == IdentityState::Unauthenticated ||
             to == IdentityState::Ready || to == IdentityState::Locked;
    case IdentityState::Ready:
      return to == IdentityState::Ready ||
             to == IdentityState::Unauthenticated ||
             to == IdentityState::Locked;
    case IdentityState::Locked:
      return to == IdentityState::Locked;
  }
  return false;
}

void IdentityManager::TransitionTo(IdentityState next) {
  std::unique_lock lock(state_mutex_);
  if (!CanTransition(state_, next)) {
    last_error_ = IdentityErrorCode::InvalidStateTransition;
    throw IdentityManagerError(IdentityErrorCode::InvalidStateTransition,
                               "Invalid identity state transition");
  }
  state_ = next;
}

void IdentityManager::SetLastError(IdentityErrorCode error) {
  std::unique_lock lock(state_mutex_);
  last_error_ = error;
}

}  // namespace veritas
