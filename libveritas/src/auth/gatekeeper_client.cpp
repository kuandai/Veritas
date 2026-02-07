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
    return grpc::InsecureChannelCredentials();
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

  const auto seconds = response.expires_at().seconds();
  result.result.expires_at =
      std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
  return result;
}

}  // namespace veritas::auth
