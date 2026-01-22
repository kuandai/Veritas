#pragma once

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

#include "gatekeeper.pb.h"
#include "fake_salt.h"
#include "session_cache.h"
#include "token_store.h"

namespace veritas::gatekeeper {

struct SaslServerOptions {
  std::string fake_salt_secret;
  std::chrono::seconds session_ttl{std::chrono::minutes(10)};
  int token_ttl_days = 30;
  std::shared_ptr<TokenStore> token_store;
};

class SaslServer {
 public:
  explicit SaslServer(SaslServerOptions options);
  ~SaslServer();

  grpc::Status BeginAuth(const veritas::auth::v1::BeginAuthRequest& request,
                         veritas::auth::v1::BeginAuthResponse* response);
  grpc::Status FinishAuth(const veritas::auth::v1::FinishAuthRequest& request,
                          veritas::auth::v1::FinishAuthResponse* response);

 private:
  void EnsureInitialized();

  SaslServerOptions options_;
  SessionCache session_cache_;
  FakeSaltGenerator fake_salt_;
  std::shared_ptr<TokenStore> token_store_;
};

}  // namespace veritas::gatekeeper
