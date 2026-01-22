#pragma once

#include <grpcpp/grpcpp.h>

#include "gatekeeper.pb.h"

namespace veritas::gatekeeper {

class SaslServer {
 public:
  SaslServer();
  ~SaslServer();

  grpc::Status BeginAuth(const veritas::auth::v1::BeginAuthRequest& request,
                         veritas::auth::v1::BeginAuthResponse* response);
  grpc::Status FinishAuth(const veritas::auth::v1::FinishAuthRequest& request,
                          veritas::auth::v1::FinishAuthResponse* response);

 private:
  void EnsureInitialized();
};

}  // namespace veritas::gatekeeper
