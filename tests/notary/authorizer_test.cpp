#include "authorizer.h"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include <gtest/gtest.h>
#include <grpcpp/server_builder.h>

#include "gatekeeper.grpc.pb.h"

namespace veritas::notary {
namespace {

class FakeTokenStatusClient final : public TokenStatusClient {
 public:
  explicit FakeTokenStatusClient(grpc::Status status,
                                 veritas::auth::v1::TokenStatusState state)
      : status_(std::move(status)), state_(state) {}

  grpc::Status GetTokenStatus(const std::string& /*refresh_token*/,
                              veritas::auth::v1::TokenStatusState* state,
                              std::string* reason) const override {
    if (status_.ok()) {
      *state = state_;
      if (reason) {
        *reason = "fake";
      }
    }
    return status_;
  }

 private:
  grpc::Status status_;
  veritas::auth::v1::TokenStatusState state_;
};

TEST(AuthorizerTest, RejectsEmptyRefreshToken) {
  auto client = std::make_shared<FakeTokenStatusClient>(
      grpc::Status::OK, veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE);
  RefreshTokenAuthorizer authorizer(client);
  const auto status = authorizer.AuthorizeRefreshToken("");
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(AuthorizerTest, AcceptsActiveToken) {
  auto client = std::make_shared<FakeTokenStatusClient>(
      grpc::Status::OK, veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE);
  RefreshTokenAuthorizer authorizer(client);
  const auto status = authorizer.AuthorizeRefreshToken("token");
  EXPECT_TRUE(status.ok());
}

TEST(AuthorizerTest, RejectsRevokedToken) {
  auto client = std::make_shared<FakeTokenStatusClient>(
      grpc::Status::OK, veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED);
  RefreshTokenAuthorizer authorizer(client);
  const auto status = authorizer.AuthorizeRefreshToken("token");
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(AuthorizerTest, RejectsUnknownTokenAsUnauthenticated) {
  auto client = std::make_shared<FakeTokenStatusClient>(
      grpc::Status::OK, veritas::auth::v1::TOKEN_STATUS_STATE_UNKNOWN);
  RefreshTokenAuthorizer authorizer(client);
  const auto status = authorizer.AuthorizeRefreshToken("token");
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(AuthorizerTest, MapsGatekeeperUnavailableToUnavailable) {
  auto client = std::make_shared<FakeTokenStatusClient>(
      grpc::Status(grpc::StatusCode::UNAVAILABLE, "down"),
      veritas::auth::v1::TOKEN_STATUS_STATE_UNSPECIFIED);
  RefreshTokenAuthorizer authorizer(client);
  const auto status = authorizer.AuthorizeRefreshToken("token");
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

class FakeGatekeeperService final : public veritas::auth::v1::Gatekeeper::Service {
 public:
  void SetState(std::string token, veritas::auth::v1::TokenStatusState state) {
    states_[std::move(token)] = state;
  }

  grpc::Status GetTokenStatus(
      grpc::ServerContext* /*context*/,
      const veritas::auth::v1::GetTokenStatusRequest* request,
      veritas::auth::v1::GetTokenStatusResponse* response) override {
    const auto it = states_.find(request->refresh_token());
    if (it == states_.end()) {
      response->set_state(veritas::auth::v1::TOKEN_STATUS_STATE_UNKNOWN);
      return grpc::Status::OK;
    }
    response->set_state(it->second);
    return grpc::Status::OK;
  }

 private:
  std::unordered_map<std::string, veritas::auth::v1::TokenStatusState> states_;
};

TEST(AuthorizerIntegrationTest, UsesGatekeeperGrpcStatusPath) {
  FakeGatekeeperService gatekeeper;
  gatekeeper.SetState("active-token",
                      veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE);
  gatekeeper.SetState("revoked-token",
                      veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED);

  grpc::ServerBuilder builder;
  int selected_port = 0;
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(),
                           &selected_port);
  builder.RegisterService(&gatekeeper);
  auto server = builder.BuildAndStart();
  ASSERT_TRUE(server != nullptr);

  GatekeeperTokenStatusClientConfig config;
  config.target = "127.0.0.1:" + std::to_string(selected_port);
  config.allow_insecure = true;
  auto client = std::make_shared<GatekeeperTokenStatusClient>(config);
  RefreshTokenAuthorizer authorizer(client);

  EXPECT_TRUE(authorizer.AuthorizeRefreshToken("active-token").ok());
  EXPECT_EQ(
      authorizer.AuthorizeRefreshToken("revoked-token").error_code(),
      grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(
      authorizer.AuthorizeRefreshToken("missing-token").error_code(),
      grpc::StatusCode::UNAUTHENTICATED);

  server->Shutdown();
}

}  // namespace
}  // namespace veritas::notary
