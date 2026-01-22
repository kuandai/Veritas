#pragma once

#include <grpcpp/grpcpp.h>

#include "gatekeeper.grpc.pb.h"
#include "rate_limiter.h"
#include "sasl_server.h"

namespace veritas::auth::v1 {

class GatekeeperServiceImpl final : public Gatekeeper::Service {
 public:
  explicit GatekeeperServiceImpl(int rate_limit_per_minute);

  grpc::Status BeginAuth(grpc::ServerContext* context,
                         const BeginAuthRequest* request,
                         BeginAuthResponse* response) override;

  grpc::Status FinishAuth(grpc::ServerContext* context,
                          const FinishAuthRequest* request,
                          FinishAuthResponse* response) override;

 private:
  veritas::gatekeeper::SaslServer sasl_server_;
  veritas::gatekeeper::RateLimiter rate_limiter_;
};

}  // namespace veritas::auth::v1
