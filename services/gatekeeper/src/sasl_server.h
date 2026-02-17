#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

#include "gatekeeper.pb.h"
#include "fake_salt.h"
#include "session_cache.h"
#include "token_store.h"

namespace veritas::gatekeeper {

struct SaslContext;

struct SaslServerOptions {
  std::string fake_salt_secret;
  std::chrono::seconds session_ttl{std::chrono::minutes(10)};
  int token_ttl_days = 30;
  std::shared_ptr<TokenStore> token_store;
  bool enable_sasl = true;
  std::string sasl_service = "veritas_gatekeeper";
  std::string sasl_mech_list = "SRP";
  std::string sasl_conf_path;
  std::string sasl_plugin_path;
  std::string sasl_dbname;
  std::string sasl_realm;
  bool skip_sasl_init = false;
  std::size_t fake_challenge_size = 512;
  std::chrono::milliseconds begin_auth_min_duration{
      std::chrono::milliseconds(8)};
#if defined(VERITAS_ENABLE_TEST_AUTH_BYPASS)
  bool allow_test_auth_bypass = false;
#endif
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
  bool UseSasl() const;

  SaslServerOptions options_;
  SessionCache session_cache_;
  FakeSaltGenerator fake_salt_;
  std::atomic<std::size_t> observed_challenge_size_;
  std::shared_ptr<TokenStore> token_store_;
  std::unique_ptr<SaslContext> sasl_context_;
};

}  // namespace veritas::gatekeeper
