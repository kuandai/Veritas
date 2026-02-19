#include "gatekeeper_client.h"

#include <chrono>
#include <stdexcept>

namespace veritas::auth {

namespace {

std::shared_ptr<grpc::ChannelCredentials> BuildCredentials(
    const GatekeeperClientConfig& config) {
  if (!config.root_cert_pem.empty()) {
    grpc::SslCredentialsOptions options;
    options.pem_root_certs = config.root_cert_pem;
    return grpc::SslCredentials(options);
  }
  if (config.allow_insecure) {
#if defined(NDEBUG)
    throw std::runtime_error(
        "Insecure Gatekeeper transport is disabled in release builds");
#else
    return grpc::InsecureChannelCredentials();
#endif
  }
  throw std::runtime_error("Gatekeeper root certificate is required");
}

}  // namespace

GatekeeperClient::GatekeeperClient(const GatekeeperClientConfig& config) {
  if (config.target.empty()) {
    throw std::runtime_error("Gatekeeper target is required");
  }
  channel_ = grpc::CreateChannel(config.target, BuildCredentials(config));
  stub_ = veritas::auth::v1::Gatekeeper::NewStub(channel_);
}

BeginAuthResult GatekeeperClient::BeginAuth(const std::string& username,
                                            std::string_view client_start) {
  veritas::auth::v1::BeginAuthRequest request;
  veritas::auth::v1::BeginAuthResponse response;
  request.set_login_username(username);
  if (!client_start.empty()) {
    request.set_client_start(client_start.data(), client_start.size());
  }

  grpc::ClientContext context;
  const grpc::Status status = stub_->BeginAuth(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "BeginAuth failed: " + status.error_message());
  }

  BeginAuthResult result;
  result.session_id = response.session_id();
  result.server_public = response.server_public();
  return result;
}

FinishAuthResult GatekeeperClient::FinishAuth(const std::string& session_id,
                                              const std::string& client_proof) {
  veritas::auth::v1::FinishAuthRequest request;
  veritas::auth::v1::FinishAuthResponse response;
  request.set_session_id(session_id);
  request.set_client_proof(client_proof);

  grpc::ClientContext context;
  const grpc::Status status = stub_->FinishAuth(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "FinishAuth failed: " + status.error_message());
  }

  FinishAuthResult result;
  result.server_proof = response.server_proof();
  result.result.user_uuid = response.user_uuid();
  result.result.refresh_token = response.refresh_token();
  result.result.issued_at = std::chrono::system_clock::now();

  const auto seconds = response.expires_at().seconds();
  result.result.expires_at =
      std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
  return result;
}

void GatekeeperClient::RevokeToken(const std::string& refresh_token,
                                   const std::string& reason) {
  veritas::auth::v1::RevokeTokenRequest request;
  veritas::auth::v1::RevokeTokenResponse response;
  request.set_refresh_token(refresh_token);
  request.set_reason(reason);

  grpc::ClientContext context;
  const grpc::Status status = stub_->RevokeToken(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "RevokeToken failed: " + status.error_message());
  }
}

TokenStatusResult GatekeeperClient::GetTokenStatus(
    const std::string& refresh_token) {
  veritas::auth::v1::GetTokenStatusRequest request;
  veritas::auth::v1::GetTokenStatusResponse response;
  request.set_refresh_token(refresh_token);

  grpc::ClientContext context;
  const grpc::Status status =
      stub_->GetTokenStatus(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "GetTokenStatus failed: " + status.error_message());
  }

  TokenStatusResult result;
  switch (response.state()) {
    case veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE:
      result.state = TokenStatusState::Active;
      break;
    case veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED:
      result.state = TokenStatusState::Revoked;
      break;
    case veritas::auth::v1::TOKEN_STATUS_STATE_UNKNOWN:
    case veritas::auth::v1::TOKEN_STATUS_STATE_UNSPECIFIED:
    default:
      result.state = TokenStatusState::Unknown;
      break;
  }
  result.reason = response.reason();
  if (response.has_revoked_at()) {
    result.revoked_at = std::chrono::system_clock::time_point(
        std::chrono::seconds(response.revoked_at().seconds()));
  }
  return result;
}

}  // namespace veritas::auth
