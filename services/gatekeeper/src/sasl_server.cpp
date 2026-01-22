#include "sasl_server.h"

#include <mutex>

#include <sasl/sasl.h>

namespace veritas::gatekeeper {

namespace {

std::once_flag g_sasl_init_once;
grpc::Status g_sasl_init_status = grpc::Status::OK;

}  // namespace

SaslServer::SaslServer() { EnsureInitialized(); }

void SaslServer::EnsureInitialized() {
  std::call_once(g_sasl_init_once, []() {
    const int result = sasl_server_init(nullptr, "veritas_gatekeeper");
    if (result != SASL_OK) {
      g_sasl_init_status = grpc::Status(grpc::StatusCode::INTERNAL,
                                        "SASL initialization failed");
      return;
    }
  });
}

grpc::Status SaslServer::BeginAuth(
    const veritas::auth::v1::BeginAuthRequest& /*request*/,
    veritas::auth::v1::BeginAuthResponse* /*response*/) {
  EnsureInitialized();
  if (!g_sasl_init_status.ok()) {
    return g_sasl_init_status;
  }
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                      "BeginAuth not implemented");
}

grpc::Status SaslServer::FinishAuth(
    const veritas::auth::v1::FinishAuthRequest& /*request*/,
    veritas::auth::v1::FinishAuthResponse* /*response*/) {
  EnsureInitialized();
  if (!g_sasl_init_status.ok()) {
    return g_sasl_init_status;
  }
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                      "FinishAuth not implemented");
}

}  // namespace veritas::gatekeeper
