#include "gatekeeper_service.h"

namespace veritas::auth::v1 {

grpc::Status GatekeeperServiceImpl::BeginAuth(grpc::ServerContext* /*context*/,
                                              const BeginAuthRequest* request,
                                              BeginAuthResponse* response) {
  return sasl_server_.BeginAuth(*request, response);
}

grpc::Status GatekeeperServiceImpl::FinishAuth(grpc::ServerContext* /*context*/,
                                               const FinishAuthRequest* request,
                                               FinishAuthResponse* response) {
  return sasl_server_.FinishAuth(*request, response);
}

}  // namespace veritas::auth::v1
