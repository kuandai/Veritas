#include "gatekeeper_client.h"

#include <cctype>
#include <chrono>
#include <stdexcept>
#include <string_view>

namespace veritas::auth {

namespace {

constexpr std::string_view kProtocolMetadataKey = "x-veritas-protocol";
constexpr std::string_view kSelectedProtocolMetadataKey =
    "x-veritas-protocol-selected";

std::string FormatProtocolVersion(std::uint32_t major, std::uint32_t minor) {
  return std::to_string(major) + "." + std::to_string(minor);
}

bool ParseProtocolVersion(std::string_view value,
                          std::uint32_t* major,
                          std::uint32_t* minor) {
  if (!major || !minor) {
    return false;
  }
  const auto dot = value.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= value.size()) {
    return false;
  }

  const std::string_view major_part = value.substr(0, dot);
  const std::string_view minor_part = value.substr(dot + 1);
  if (major_part.empty() || minor_part.empty()) {
    return false;
  }
  for (const char ch : major_part) {
    if (!std::isdigit(static_cast<unsigned char>(ch))) {
      return false;
    }
  }
  for (const char ch : minor_part) {
    if (!std::isdigit(static_cast<unsigned char>(ch))) {
      return false;
    }
  }

  try {
    *major = static_cast<std::uint32_t>(std::stoul(std::string(major_part)));
    *minor = static_cast<std::uint32_t>(std::stoul(std::string(minor_part)));
  } catch (const std::exception&) {
    return false;
  }
  return true;
}

void AttachProtocolMetadata(grpc::ClientContext* context,
                            const GatekeeperClientConfig& config) {
  if (!context) {
    return;
  }
  context->AddMetadata(std::string(kProtocolMetadataKey),
                       FormatProtocolVersion(config.protocol_major,
                                             config.protocol_minor));
}

void ValidateNegotiatedVersion(const grpc::ClientContext& context,
                               const GatekeeperClientConfig& config) {
  const auto& metadata = context.GetServerInitialMetadata();
  const auto it = metadata.find(std::string(kSelectedProtocolMetadataKey));
  if (it == metadata.end()) {
    throw std::runtime_error(
        "Gatekeeper did not return negotiated protocol version metadata");
  }

  const std::string_view value(it->second.data(), it->second.length());
  std::uint32_t selected_major = 0;
  std::uint32_t selected_minor = 0;
  if (!ParseProtocolVersion(value, &selected_major, &selected_minor)) {
    throw std::runtime_error("Gatekeeper returned malformed protocol version");
  }

  if (selected_major != config.protocol_major) {
    throw std::runtime_error("Gatekeeper negotiated an unsupported major version");
  }
  if (selected_minor > config.protocol_minor) {
    throw std::runtime_error("Gatekeeper negotiated a newer minor version");
  }
}

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

GatekeeperClient::GatekeeperClient(const GatekeeperClientConfig& config)
    : config_(config) {
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
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->BeginAuth(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "BeginAuth failed: " + status.error_message());
  }
  ValidateNegotiatedVersion(context, config_);

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
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->FinishAuth(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "FinishAuth failed: " + status.error_message());
  }
  ValidateNegotiatedVersion(context, config_);

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
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->RevokeToken(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "RevokeToken failed: " + status.error_message());
  }
  ValidateNegotiatedVersion(context, config_);
}

TokenStatusResult GatekeeperClient::GetTokenStatus(
    const std::string& refresh_token) {
  veritas::auth::v1::GetTokenStatusRequest request;
  veritas::auth::v1::GetTokenStatusResponse response;
  request.set_refresh_token(refresh_token);

  grpc::ClientContext context;
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status =
      stub_->GetTokenStatus(&context, request, &response);
  if (!status.ok()) {
    throw GatekeeperError(status.error_code(),
                          "GetTokenStatus failed: " + status.error_message());
  }
  ValidateNegotiatedVersion(context, config_);

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
