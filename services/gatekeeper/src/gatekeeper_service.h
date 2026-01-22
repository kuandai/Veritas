#pragma once

#include <grpcpp/grpcpp.h>

#include "auth_metrics.h"
#include "gatekeeper.grpc.pb.h"
#include "rate_limiter.h"
#include "sasl_server.h"

namespace veritas::auth::v1 {

class GatekeeperServiceImpl final : public Gatekeeper::Service {
 public:
  GatekeeperServiceImpl(int rate_limit_per_minute,
                        veritas::gatekeeper::SaslServerOptions options);

  grpc::Status BeginAuth(grpc::ServerContext* context,
                         const BeginAuthRequest* request,
                         BeginAuthResponse* response) override;

  grpc::Status FinishAuth(grpc::ServerContext* context,
                          const FinishAuthRequest* request,
                          FinishAuthResponse* response) override;

 private:
  veritas::gatekeeper::SaslServer sasl_server_;
  veritas::gatekeeper::RateLimiter rate_limiter_;
  veritas::gatekeeper::AuthMetrics metrics_;
};

}  // namespace veritas::auth::v1
