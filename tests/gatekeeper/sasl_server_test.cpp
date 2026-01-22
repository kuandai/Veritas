#include "sasl_server.h"

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

namespace veritas::gatekeeper {
namespace {

class FailingTokenStore final : public TokenStore {
 public:
  void PutToken(const TokenRecord& /*record*/) override {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "token store unavailable");
  }

  std::optional<TokenRecord> GetToken(const std::string& /*token_hash*/) override {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "token store unavailable");
  }

  void RevokeUser(const std::string& /*user_uuid*/) override {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "token store unavailable");
  }
};

SaslServerOptions DefaultOptions() {
  SaslServerOptions options;
  options.fake_salt_secret = "test-secret";
  options.token_ttl_days = 1;
  return options;
}

}  // namespace

TEST(SaslServerTest, BeginAuthRejectsEmptyUsername) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::BeginAuthRequest request;
  veritas::auth::v1::BeginAuthResponse response;

  const grpc::Status status = server.BeginAuth(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(SaslServerTest, BeginAuthAcceptsLargeUsername) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::BeginAuthRequest request;
  veritas::auth::v1::BeginAuthResponse response;
  request.set_login_username(std::string(4096, 'a'));

  const grpc::Status status = server.BeginAuth(request, &response);
  EXPECT_TRUE(status.ok());
}

TEST(SaslServerTest, FinishAuthRejectsEmptySessionId) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::FinishAuthRequest request;
  veritas::auth::v1::FinishAuthResponse response;

  const grpc::Status status = server.FinishAuth(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(SaslServerTest, FinishAuthRejectsEmptyProof) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::FinishAuthRequest request;
  veritas::auth::v1::FinishAuthResponse response;
  request.set_session_id("session");

  const grpc::Status status = server.FinishAuth(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(SaslServerTest, FinishAuthUnknownSessionIsUnauthenticated) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::FinishAuthRequest request;
  veritas::auth::v1::FinishAuthResponse response;
  request.set_session_id("missing-session");
  request.set_client_proof("proof");

  const grpc::Status status = server.FinishAuth(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(SaslServerTest, FinishAuthReturnsTokenAndUuid) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username("alice");

  ASSERT_TRUE(server.BeginAuth(begin_request, &begin_response).ok());

  veritas::auth::v1::FinishAuthRequest finish_request;
  veritas::auth::v1::FinishAuthResponse finish_response;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof("proof");

  const auto start =
      std::chrono::system_clock::now().time_since_epoch();
  const grpc::Status status = server.FinishAuth(finish_request, &finish_response);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(finish_response.refresh_token().empty());
  EXPECT_FALSE(finish_response.user_uuid().empty());

  const auto now_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(start).count();
  const auto expires_at = finish_response.expires_at().seconds();
  const auto expected = now_seconds + 24 * 60 * 60;
  EXPECT_GE(expires_at, expected - 5);
  EXPECT_LE(expires_at, expected + 5);
}

TEST(SaslServerTest, FinishAuthSessionReplayFails) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username("alice");
  ASSERT_TRUE(server.BeginAuth(begin_request, &begin_response).ok());

  veritas::auth::v1::FinishAuthRequest finish_request;
  veritas::auth::v1::FinishAuthResponse finish_response;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof("proof");
  ASSERT_TRUE(server.FinishAuth(finish_request, &finish_response).ok());

  veritas::auth::v1::FinishAuthResponse second_response;
  const grpc::Status status = server.FinishAuth(finish_request, &second_response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(SaslServerTest, TokenStoreUnavailableMapsToGrpcUnavailable) {
  auto failing_store = std::make_shared<FailingTokenStore>();
  SaslServerOptions options = DefaultOptions();
  options.token_store = failing_store;
  SaslServer server(options);

  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username("alice");
  ASSERT_TRUE(server.BeginAuth(begin_request, &begin_response).ok());

  veritas::auth::v1::FinishAuthRequest finish_request;
  veritas::auth::v1::FinishAuthResponse finish_response;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof("proof");

  const grpc::Status status = server.FinishAuth(finish_request, &finish_response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

}  // namespace veritas::gatekeeper
