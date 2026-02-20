#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <grpcpp/support/status.h>

#include "gatekeeper.grpc.pb.h"

namespace veritas::notary {

struct GatekeeperTokenStatusClientConfig {
  std::string target;
  std::string root_ca_pem;
  bool allow_insecure = false;
};

class TokenStatusClient {
 public:
  virtual ~TokenStatusClient() = default;

  virtual grpc::Status GetTokenStatus(
      const std::string& refresh_token,
      veritas::auth::v1::TokenStatusState* state,
      std::string* reason) const = 0;
};

class GatekeeperTokenStatusClient final : public TokenStatusClient {
 public:
  explicit GatekeeperTokenStatusClient(
      const GatekeeperTokenStatusClientConfig& config);

  grpc::Status GetTokenStatus(
      const std::string& refresh_token,
      veritas::auth::v1::TokenStatusState* state,
      std::string* reason) const override;

 private:
  std::unique_ptr<veritas::auth::v1::Gatekeeper::Stub> stub_;
};

class RequestAuthorizer {
 public:
  virtual ~RequestAuthorizer() = default;
  virtual grpc::Status AuthorizeRefreshToken(
      std::string_view refresh_token) const = 0;
};

class RefreshTokenAuthorizer final : public RequestAuthorizer {
 public:
  explicit RefreshTokenAuthorizer(std::shared_ptr<TokenStatusClient> client);

  grpc::Status AuthorizeRefreshToken(
      std::string_view refresh_token) const override;

 private:
  std::shared_ptr<TokenStatusClient> client_;
};

}  // namespace veritas::notary
