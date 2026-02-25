#include "authorizer.h"

#include <stdexcept>

#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "gatekeeper.grpc.pb.h"

namespace veritas::notary {

namespace {

constexpr const char* kProtocolMetadataKey = "x-veritas-protocol";
constexpr const char* kProtocolVersionValue = "1.0";

}  // namespace

GatekeeperTokenStatusClient::GatekeeperTokenStatusClient(
    const GatekeeperTokenStatusClientConfig& config) {
  if (config.target.empty()) {
    throw std::runtime_error("gatekeeper target is required");
  }

  std::shared_ptr<grpc::ChannelCredentials> credentials;
  if (config.allow_insecure) {
    credentials = grpc::InsecureChannelCredentials();
  } else {
    if (config.root_ca_pem.empty()) {
      throw std::runtime_error(
          "gatekeeper root CA is required for secure transport");
    }
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = config.root_ca_pem;
    credentials = grpc::SslCredentials(ssl_opts);
  }

  auto channel = grpc::CreateChannel(config.target, credentials);
  stub_ = veritas::auth::v1::Gatekeeper::NewStub(channel);
}

grpc::Status GatekeeperTokenStatusClient::GetTokenStatus(
    const std::string& refresh_token,
    veritas::auth::v1::TokenStatusState* state,
    std::string* reason,
    std::string* user_uuid) const {
  if (!state) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "state output parameter is required");
  }

  veritas::auth::v1::GetTokenStatusRequest request;
  veritas::auth::v1::GetTokenStatusResponse response;
  request.set_refresh_token(refresh_token);

  grpc::ClientContext context;
  context.AddMetadata(kProtocolMetadataKey, kProtocolVersionValue);
  const auto status = stub_->GetTokenStatus(&context, request, &response);
  if (!status.ok()) {
    return status;
  }
  *state = response.state();
  if (reason) {
    *reason = response.reason();
  }
  if (user_uuid) {
    *user_uuid = response.user_uuid();
  }
  return grpc::Status::OK;
}

RefreshTokenAuthorizer::RefreshTokenAuthorizer(
    std::shared_ptr<TokenStatusClient> client)
    : client_(std::move(client)) {
  if (!client_) {
    throw std::runtime_error("token status client is required");
  }
}

grpc::Status RefreshTokenAuthorizer::AuthorizeRefreshToken(
    std::string_view refresh_token,
    std::string* user_uuid) const {
  if (refresh_token.empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "refresh_token is required");
  }

  veritas::auth::v1::TokenStatusState state =
      veritas::auth::v1::TOKEN_STATUS_STATE_UNSPECIFIED;
  std::string reason;
  std::string principal_user_uuid;
  const auto status = client_->GetTokenStatus(std::string(refresh_token), &state,
                                              &reason, &principal_user_uuid);
  if (!status.ok()) {
    if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
      return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                          "gatekeeper is unavailable");
    }
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "failed to validate refresh token");
  }

  switch (state) {
    case veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE:
      if (principal_user_uuid.empty()) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                            "refresh token is missing principal identity");
      }
      if (user_uuid) {
        *user_uuid = std::move(principal_user_uuid);
      }
      return grpc::Status::OK;
    case veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED:
      return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                          "refresh token is revoked");
    case veritas::auth::v1::TOKEN_STATUS_STATE_UNKNOWN:
    case veritas::auth::v1::TOKEN_STATUS_STATE_UNSPECIFIED:
    default:
      return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                          "refresh token is invalid or expired");
  }
}

}  // namespace veritas::notary
