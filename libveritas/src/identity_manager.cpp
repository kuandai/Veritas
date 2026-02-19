#include "veritas/identity_manager.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <random>
#include <stdexcept>
#include <thread>
#include <utility>

#include <grpcpp/grpcpp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "auth/auth_flow.h"
#include "auth/gatekeeper_client.h"

namespace veritas {

namespace {

class LambdaRotationCredentialProvider final : public RotationCredentialProvider {
 public:
  explicit LambdaRotationCredentialProvider(CredentialProvider fn)
      : fn_(std::move(fn)) {}

  std::string GetCredential() override {
    if (!fn_) {
      throw std::runtime_error("rotation credential provider is not configured");
    }
    return fn_();
  }

 private:
  CredentialProvider fn_;
};

struct BioDeleter {
  void operator()(BIO* bio) const { BIO_free(bio); }
};

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

std::string Trim(std::string value) {
  const auto begin = std::find_if_not(value.begin(), value.end(),
                                      [](unsigned char ch) {
                                        return std::isspace(ch) != 0;
                                      });
  const auto end = std::find_if_not(value.rbegin(), value.rend(),
                                    [](unsigned char ch) {
                                      return std::isspace(ch) != 0;
                                    })
                       .base();
  if (begin >= end) {
    return {};
  }
  return std::string(begin, end);
}

std::vector<unsigned char> EncodeAlpnList(const std::string& alpn) {
  if (alpn.empty()) {
    throw std::runtime_error("ALPN is required");
  }
  std::vector<unsigned char> encoded;
  std::size_t start = 0;
  while (start <= alpn.size()) {
    const std::size_t comma = alpn.find(',', start);
    std::string token =
        Trim(alpn.substr(start, comma == std::string::npos
                                    ? std::string::npos
                                    : comma - start));
    if (token.empty()) {
      throw std::runtime_error("ALPN contains an empty token");
    }
    if (token.size() > 255) {
      throw std::runtime_error("ALPN token exceeds 255 bytes");
    }
    encoded.push_back(static_cast<unsigned char>(token.size()));
    encoded.insert(encoded.end(), token.begin(), token.end());
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  return encoded;
}

std::vector<std::unique_ptr<X509, X509Deleter>> ParseCertificateChain(
    const std::string& pem_chain) {
  std::vector<std::unique_ptr<X509, X509Deleter>> certs;
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(pem_chain.data(), static_cast<int>(pem_chain.size())));
  if (!bio) {
    throw std::runtime_error("failed to allocate certificate BIO");
  }

  while (true) {
    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
      break;
    }
    certs.emplace_back(cert);
  }

  if (certs.empty()) {
    throw std::runtime_error("certificate_chain_pem must contain certificates");
  }
  if (certs.size() < 2) {
    throw std::runtime_error(
        "certificate_chain_pem must include leaf and intermediate chain");
  }
  return certs;
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> ParsePrivateKey(
    const std::string& private_key_pem) {
  std::unique_ptr<BIO, BioDeleter> bio(BIO_new_mem_buf(
      private_key_pem.data(), static_cast<int>(private_key_pem.size())));
  if (!bio) {
    throw std::runtime_error("failed to allocate key BIO");
  }
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (!key) {
    throw std::runtime_error("private_key_pem is invalid");
  }
  return std::unique_ptr<EVP_PKEY, PkeyDeleter>(key);
}

std::shared_ptr<SSL_CTX> BuildSecurityContext(const TransportContextConfig& config) {
  if (config.certificate_chain_pem.empty()) {
    throw std::runtime_error("certificate_chain_pem is required");
  }
  if (config.private_key_pem.empty()) {
    throw std::runtime_error("private_key_pem is required");
  }
  const std::vector<unsigned char> alpn = EncodeAlpnList(config.alpn);
  auto certs = ParseCertificateChain(config.certificate_chain_pem);
  auto private_key = ParsePrivateKey(config.private_key_pem);

  SSL_CTX* raw_ctx = SSL_CTX_new(TLS_client_method());
  if (!raw_ctx) {
    throw std::runtime_error("failed to allocate SSL_CTX");
  }
  std::shared_ptr<SSL_CTX> ctx(raw_ctx, [](SSL_CTX* value) {
    if (value) {
      SSL_CTX_free(value);
    }
  });

  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);

  if (SSL_CTX_use_certificate(ctx.get(), certs.front().get()) != 1) {
    throw std::runtime_error("failed to load leaf certificate");
  }
  if (SSL_CTX_use_PrivateKey(ctx.get(), private_key.get()) != 1) {
    throw std::runtime_error("failed to load private key");
  }
  if (SSL_CTX_check_private_key(ctx.get()) != 1) {
    throw std::runtime_error("private key does not match leaf certificate");
  }
  for (std::size_t i = 1; i < certs.size(); ++i) {
    X509* dup = X509_dup(certs[i].get());
    if (!dup || SSL_CTX_add_extra_chain_cert(ctx.get(), dup) != 1) {
      if (dup) {
        X509_free(dup);
      }
      throw std::runtime_error("failed to add intermediate certificate");
    }
  }
  if (SSL_CTX_set_alpn_protos(ctx.get(), alpn.data(),
                              static_cast<unsigned int>(alpn.size())) != 0) {
    throw std::runtime_error("failed to configure ALPN protocols");
  }
  return ctx;
}

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
  result.issued_at = std::chrono::system_clock::now();
  return result;
}

double ClampRatio(double value) {
  if (std::isnan(value)) {
    return 0.70;
  }
  return std::clamp(value, 0.0, 1.0);
}

double RandomUnit() {
  thread_local std::mt19937_64 generator(std::random_device{}());
  thread_local std::uniform_real_distribution<double> distribution(0.0, 1.0);
  return distribution(generator);
}

}  // namespace

IdentityManager::IdentityManager(CredentialProvider credential_provider,
                                 std::optional<storage::TokenStoreConfig> token_store_config,
                                 EntropyChecker entropy_checker,
                                 AuthRunner auth_runner)
    : credential_provider_(std::move(credential_provider)),
      entropy_checker_(std::move(entropy_checker)),
      auth_runner_(std::move(auth_runner)) {
  if (credential_provider_) {
    rotation_provider_ =
        std::make_shared<LambdaRotationCredentialProvider>(credential_provider_);
  }

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

IdentityManager::~IdentityManager() {
  StopRotation();
  StopRevocationMonitor();
}

SecurityContext IdentityManager::get_quic_context() {
  std::shared_lock lock(context_mutex_);
  SecurityContext context;
  context.handle = security_context_;
  context.ctx = security_context_.get();
  return context;
}

void IdentityManager::UpdateSecurityContext(const TransportContextConfig& config) {
  std::shared_ptr<SSL_CTX> next = BuildSecurityContext(config);
  std::unique_lock lock(context_mutex_);
  security_context_ = std::move(next);
}

AuthResult IdentityManager::RunAuthFlow(const GatekeeperClientConfig& config,
                                        const std::string& username,
                                        const std::string& password) {
  if (auth_runner_) {
    return auth_runner_(config, username, password);
  }
  veritas::auth::AuthFlow flow(config);
  return flow.Authenticate(username, password);
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
        entropy.message.empty() ? "entropy preflight did not report readiness"
                                : entropy.message);
  }
  if (GetState() == IdentityState::Locked) {
    SetLastError(IdentityErrorCode::InvalidStateTransition);
    throw IdentityManagerError(IdentityErrorCode::InvalidStateTransition,
                               "identity is locked");
  }

  try {
    AuthResult result = RunAuthFlow(config, username, password);
    if (result.issued_at.time_since_epoch().count() == 0) {
      result.issued_at = std::chrono::system_clock::now();
    }

    {
      std::unique_lock lock(state_mutex_);
      persisted_identity_ = result;
    }
    if (token_store_) {
      token_store_->Save(ToStoredIdentity(result));
    }
    TransitionTo(IdentityState::Ready);
    SetLastError(IdentityErrorCode::None);
    consecutive_auth_failures_.store(0);
    EmitAnalytics(AnalyticsEventType::AuthSuccess, 1, "");
    return result;
  } catch (const storage::TokenStoreError&) {
    SetLastError(IdentityErrorCode::PersistenceFailure);
    throw;
  } catch (const IdentityManagerError&) {
    const int failure_count = consecutive_auth_failures_.fetch_add(1) + 1;
    EmitAnalytics(AnalyticsEventType::AuthFailure, failure_count,
                  "identity manager error");
    if (failure_count >= 3) {
      EmitAlert(AlertType::RepeatedAuthFailures);
    }
    throw;
  } catch (const veritas::auth::GatekeeperError& ex) {
    const int failure_count = consecutive_auth_failures_.fetch_add(1) + 1;
    if (ex.code() == grpc::StatusCode::UNAVAILABLE) {
      SetLastError(IdentityErrorCode::AuthServerUnavailable);
      EmitAlert(AlertType::AuthServerUnreachable);
      EmitAnalytics(AnalyticsEventType::AuthFailure, failure_count,
                    "auth_server_unavailable");
      throw IdentityManagerError(IdentityErrorCode::AuthServerUnavailable,
                                 ex.what());
    }
    SetLastError(IdentityErrorCode::AuthenticationFailed);
    EmitAnalytics(AnalyticsEventType::AuthFailure, failure_count,
                  "authentication_failed");
    if (failure_count >= 3) {
      EmitAlert(AlertType::RepeatedAuthFailures);
    }
    throw IdentityManagerError(IdentityErrorCode::AuthenticationFailed,
                               ex.what());
  } catch (const std::exception& ex) {
    const int failure_count = consecutive_auth_failures_.fetch_add(1) + 1;
    SetLastError(IdentityErrorCode::AuthenticationFailed);
    EmitAnalytics(AnalyticsEventType::AuthFailure, failure_count,
                  "authentication_failed");
    if (failure_count >= 3) {
      EmitAlert(AlertType::RepeatedAuthFailures);
    }
    throw IdentityManagerError(IdentityErrorCode::AuthenticationFailed,
                               ex.what());
  }
}

AuthResult IdentityManager::Authenticate(const GatekeeperClientConfig& config,
                                         const std::string& username) {
  if (!credential_provider_) {
    SetLastError(IdentityErrorCode::MissingCredentialProvider);
    throw IdentityManagerError(IdentityErrorCode::MissingCredentialProvider,
                               "credential provider is not configured");
  }
  return Authenticate(config, username, credential_provider_());
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
  if (GetState() == IdentityState::Locked) {
    SetLastError(IdentityErrorCode::InvalidStateTransition);
    throw IdentityManagerError(IdentityErrorCode::InvalidStateTransition,
                               "identity is locked");
  }

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

void IdentityManager::SetRotationCredentialProvider(
    std::shared_ptr<RotationCredentialProvider> provider) {
  std::lock_guard<std::mutex> lock(rotation_mutex_);
  rotation_provider_ = std::move(provider);
}

std::chrono::system_clock::time_point IdentityManager::ComputeRotationDeadline(
    const AuthResult& identity,
    double refresh_ratio,
    std::chrono::system_clock::time_point now) {
  const auto ratio = ClampRatio(refresh_ratio);
  auto issued_at = identity.issued_at;
  if (issued_at.time_since_epoch().count() <= 0 || issued_at >= identity.expires_at ||
      issued_at > now) {
    issued_at = now;
  }
  if (identity.expires_at <= issued_at) {
    return now;
  }
  const auto lifetime = identity.expires_at - issued_at;
  const auto offset = std::chrono::duration_cast<std::chrono::system_clock::duration>(
      lifetime * ratio);
  const auto deadline = issued_at + offset;
  return deadline < now ? now : deadline;
}

std::chrono::milliseconds IdentityManager::ComputeBackoffDelay(
    int attempt,
    std::chrono::milliseconds initial,
    std::chrono::milliseconds max,
    double jitter_ratio,
    double jitter_sample) {
  if (attempt < 1) {
    attempt = 1;
  }
  if (initial.count() < 1) {
    initial = std::chrono::milliseconds(1);
  }
  if (max < initial) {
    max = initial;
  }

  const auto capped_attempt = std::min(attempt - 1, 20);
  std::int64_t base = initial.count();
  for (int i = 0; i < capped_attempt && base < max.count(); ++i) {
    base = std::min<std::int64_t>(base * 2, max.count());
  }

  const double clamped_jitter = std::clamp(jitter_ratio, 0.0, 1.0);
  const double sample = std::clamp(jitter_sample, 0.0, 1.0);
  const double signed_sample = (sample * 2.0) - 1.0;
  const double jitter_delta = static_cast<double>(base) * clamped_jitter * signed_sample;
  const std::int64_t with_jitter = static_cast<std::int64_t>(
      std::round(static_cast<double>(base) + jitter_delta));
  const std::int64_t clamped =
      std::clamp<std::int64_t>(with_jitter, 1, max.count());
  return std::chrono::milliseconds(clamped);
}

void IdentityManager::StartRotation(const GatekeeperClientConfig& config,
                                    const std::string& username,
                                    RotationPolicy policy) {
  if (config.target.empty()) {
    throw std::runtime_error("rotation target is required");
  }
  if (username.empty()) {
    throw std::runtime_error("rotation username is required");
  }

  StopRotation();
  {
    std::lock_guard<std::mutex> lock(rotation_mutex_);
    rotation_config_ = config;
    rotation_username_ = username;
    rotation_policy_ = policy;
    if (!rotation_provider_ && credential_provider_) {
      rotation_provider_ =
          std::make_shared<LambdaRotationCredentialProvider>(credential_provider_);
    }
  }

  rotation_running_.store(true);
  rotation_worker_ = std::jthread([this](std::stop_token token) {
    RotationLoop(token);
  });
}

void IdentityManager::StopRotation() {
  if (rotation_worker_.joinable()) {
    rotation_worker_.request_stop();
    rotation_worker_.join();
  }
  rotation_running_.store(false);
}

bool IdentityManager::IsRotationRunning() const {
  return rotation_running_.load();
}

void IdentityManager::StartRevocationMonitor(const GatekeeperClientConfig& config,
                                             RevocationPolicy policy) {
  if (config.target.empty()) {
    throw std::runtime_error("revocation monitor target is required");
  }
  if (policy.poll_interval.count() <= 0) {
    throw std::runtime_error("revocation poll interval must be positive");
  }
  if (policy.poll_interval >
      std::chrono::duration_cast<std::chrono::milliseconds>(policy.lock_deadline)) {
    throw std::runtime_error(
        "revocation poll interval must not exceed lock deadline");
  }

  StopRevocationMonitor();
  {
    std::lock_guard<std::mutex> lock(rotation_mutex_);
    revocation_config_ = config;
    revocation_policy_ = policy;
  }
  revocation_running_.store(true);
  revocation_worker_ = std::jthread([this](std::stop_token token) {
    RevocationLoop(token);
  });
}

void IdentityManager::StopRevocationMonitor() {
  if (revocation_worker_.joinable()) {
    revocation_worker_.request_stop();
    revocation_worker_.join();
  }
  revocation_running_.store(false);
}

bool IdentityManager::IsRevocationMonitorRunning() const {
  return revocation_running_.load();
}

bool IdentityManager::SleepWithStop(std::stop_token stop_token,
                                    std::chrono::milliseconds wait) {
  if (wait.count() <= 0) {
    return !stop_token.stop_requested();
  }
  const auto chunk = std::chrono::milliseconds(25);
  std::chrono::milliseconds remaining = wait;
  while (remaining.count() > 0) {
    if (stop_token.stop_requested()) {
      return false;
    }
    const auto current = remaining > chunk ? chunk : remaining;
    std::this_thread::sleep_for(current);
    remaining -= current;
  }
  return !stop_token.stop_requested();
}

void IdentityManager::RotationLoop(std::stop_token stop_token) {
  int consecutive_rotation_failures = 0;
  while (!stop_token.stop_requested()) {
    RotationPolicy policy;
    GatekeeperClientConfig config;
    std::string username;
    std::shared_ptr<RotationCredentialProvider> provider;
    {
      std::lock_guard<std::mutex> lock(rotation_mutex_);
      policy = rotation_policy_;
      config = rotation_config_;
      username = rotation_username_;
      provider = rotation_provider_;
    }

    if (!provider) {
      EmitAlert(AlertType::RotationFailure);
      SleepWithStop(stop_token, policy.minimum_interval);
      continue;
    }

    const auto persisted = GetPersistedIdentity();
    if (!persisted.has_value()) {
      SleepWithStop(stop_token, policy.minimum_interval);
      continue;
    }

    const auto now = std::chrono::system_clock::now();
    const auto deadline = ComputeRotationDeadline(*persisted, policy.refresh_ratio, now);
    if (deadline > now) {
      const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - now);
      if (!SleepWithStop(stop_token, wait)) {
        break;
      }
    }

    bool rotated = false;
    for (int attempt = 1; attempt <= std::max(1, policy.max_retries); ++attempt) {
      if (stop_token.stop_requested()) {
        break;
      }
      try {
        const std::string credential = provider->GetCredential();
        Authenticate(config, username, credential);
        consecutive_rotation_failures = 0;
        rotated = true;
        if (rotation_callback_) {
          rotation_callback_();
        }
        EmitAnalytics(AnalyticsEventType::RotationSuccess, 1, "");
        break;
      } catch (const IdentityManagerError& ex) {
        ++consecutive_rotation_failures;
        EmitAlert(AlertType::RotationFailure);
        std::string detail = "rotation_failed";
        if (ex.code() == IdentityErrorCode::AuthServerUnavailable) {
          detail = "auth_server_unavailable";
        } else if (ex.code() == IdentityErrorCode::EntropyUnavailable) {
          detail = "entropy_unavailable";
        }
        EmitAnalytics(AnalyticsEventType::RotationFailure,
                      consecutive_rotation_failures, detail);
        if (ex.code() == IdentityErrorCode::AuthServerUnavailable) {
          EmitAlert(AlertType::AuthServerUnreachable);
        }
        if (attempt >= std::max(1, policy.max_retries)) {
          if (consecutive_rotation_failures >= std::max(1, policy.max_retries)) {
            EmitAlert(AlertType::PersistentRotationFailure);
          }
          const auto current = GetPersistedIdentity();
          const auto now = std::chrono::system_clock::now();
          if (current.has_value() &&
              now > current->expires_at + policy.lkg_grace_period) {
            try {
              Lock();
            } catch (const std::exception&) {
            }
          }
          break;
        }
        const auto delay = ComputeBackoffDelay(
            attempt, policy.retry_initial, policy.retry_max, policy.jitter_ratio,
            RandomUnit());
        if (!SleepWithStop(stop_token, delay)) {
          break;
        }
      }
    }

    if (!rotated) {
      if (!SleepWithStop(stop_token, policy.minimum_interval)) {
        break;
      }
    }
  }
  rotation_running_.store(false);
}

void IdentityManager::RevocationLoop(std::stop_token stop_token) {
  while (!stop_token.stop_requested()) {
    GatekeeperClientConfig config;
    RevocationPolicy policy;
    {
      std::lock_guard<std::mutex> lock(rotation_mutex_);
      config = revocation_config_;
      policy = revocation_policy_;
    }

    const auto current = GetPersistedIdentity();
    if (!current.has_value() || current->refresh_token.empty()) {
      if (!SleepWithStop(stop_token, policy.poll_interval)) {
        break;
      }
      continue;
    }

    try {
      veritas::auth::GatekeeperClient client(config);
      const auto status = client.GetTokenStatus(current->refresh_token);
      if (status.state == veritas::auth::TokenStatusState::Revoked) {
        EmitAlert(AlertType::TokenRevoked);
        EmitAnalytics(AnalyticsEventType::RevocationDetected, 1, status.reason);
        try {
          Lock();
        } catch (const std::exception&) {
        }
        break;
      }
    } catch (const std::exception&) {
      // Keep polling; revocation monitoring should not break auth flow on errors.
    }

    if (!SleepWithStop(stop_token, policy.poll_interval)) {
      break;
    }
  }
  revocation_running_.store(false);
}

void IdentityManager::on_rotation(RotationCallback callback) {
  rotation_callback_ = std::move(callback);
}

void IdentityManager::on_security_alert(SecurityAlertCallback callback) {
  security_alert_callback_ = std::move(callback);
}

void IdentityManager::on_analytics(AnalyticsCallback callback) {
  analytics_callback_ = std::move(callback);
}

void IdentityManager::set_log_handler(LogHandler handler) {
  log_handler_ = std::move(handler);
}

void IdentityManager::EmitAlert(AlertType alert) {
  if (security_alert_callback_) {
    security_alert_callback_(alert);
  }
}

void IdentityManager::EmitAnalytics(AnalyticsEventType type,
                                    int count,
                                    const std::string& detail) {
  if (!analytics_callback_) {
    return;
  }
  AnalyticsEvent event;
  event.type = type;
  event.count = count;
  event.detail = detail;
  analytics_callback_(event);
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
                               "invalid identity state transition");
  }
  state_ = next;
}

void IdentityManager::SetLastError(IdentityErrorCode error) {
  std::unique_lock lock(state_mutex_);
  last_error_ = error;
}

}  // namespace veritas
