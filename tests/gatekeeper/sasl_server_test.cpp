#include "sasl_server.h"

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

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

  TokenStatus GetTokenStatus(const std::string& /*token_hash*/) override {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "token store unavailable");
  }

  void RevokeToken(const std::string& /*token_hash*/,
                   const std::string& /*reason*/) override {
    throw TokenStoreError(TokenStoreError::Kind::Unavailable,
                          "token store unavailable");
  }

  void RotateTokensForUser(const std::string& /*user_uuid*/,
                           std::chrono::seconds /*grace_ttl*/) override {
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
  options.skip_sasl_init = true;
#if defined(VERITAS_ENABLE_TEST_AUTH_BYPASS)
  options.allow_test_auth_bypass = true;
#endif
  return options;
}

}  // namespace

TEST(SaslServerTest, ConstructorRejectsAuthBypassWithoutExplicitTestFlag) {
  SaslServerOptions options = DefaultOptions();
  options.enable_sasl = false;
#if defined(VERITAS_ENABLE_TEST_AUTH_BYPASS)
  options.allow_test_auth_bypass = false;
#endif
  EXPECT_THROW(SaslServer server(options), std::runtime_error);
}

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

TEST(SaslServerTest, BeginAuthUsesConfiguredFakeChallengeSize) {
  SaslServerOptions options = DefaultOptions();
  options.fake_challenge_size = 96;
  SaslServer server(options);

  veritas::auth::v1::BeginAuthRequest request;
  veritas::auth::v1::BeginAuthResponse response;
  request.set_login_username("alice");

  const grpc::Status status = server.BeginAuth(request, &response);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(response.server_public().size(), 96u);
}

TEST(SaslServerTest, BeginAuthHonorsMinimumLatencyBudget) {
  SaslServerOptions options = DefaultOptions();
  options.begin_auth_min_duration = std::chrono::milliseconds(15);
  SaslServer server(options);

  veritas::auth::v1::BeginAuthRequest request;
  veritas::auth::v1::BeginAuthResponse response;
  request.set_login_username("alice");

  const auto started = std::chrono::steady_clock::now();
  const grpc::Status status = server.BeginAuth(request, &response);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - started);

  ASSERT_TRUE(status.ok());
  EXPECT_GE(elapsed.count(), 10);
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

TEST(SaslServerTest, FinishAuthSessionReplayReturnsCachedResult) {
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
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(second_response.refresh_token(), finish_response.refresh_token());
  EXPECT_EQ(second_response.server_proof(), finish_response.server_proof());
  EXPECT_EQ(second_response.user_uuid(), finish_response.user_uuid());
}

TEST(SaslServerTest, FinishAuthReplayRejectsProofMismatch) {
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

  veritas::auth::v1::FinishAuthRequest replay_request;
  replay_request.set_session_id(begin_response.session_id());
  replay_request.set_client_proof("different-proof");
  veritas::auth::v1::FinishAuthResponse replay_response;
  const grpc::Status status = server.FinishAuth(replay_request, &replay_response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(SaslServerTest, FinishAuthConcurrentCallsAllowSingleSuccess) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username("alice");
  ASSERT_TRUE(server.BeginAuth(begin_request, &begin_response).ok());

  veritas::auth::v1::FinishAuthRequest finish_request;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof("proof");

  std::array<grpc::Status, 2> statuses{
      grpc::Status::OK, grpc::Status::OK};
  std::array<veritas::auth::v1::FinishAuthResponse, 2> responses;

  std::atomic<int> ready{0};
  auto run = [&](std::size_t index) {
    ready.fetch_add(1, std::memory_order_release);
    while (ready.load(std::memory_order_acquire) < 2) {
      std::this_thread::yield();
    }
    statuses[index] = server.FinishAuth(finish_request, &responses[index]);
  };

  std::thread first(run, 0);
  std::thread second(run, 1);
  first.join();
  second.join();

  int success_count = 0;
  int unauthenticated_count = 0;
  for (const auto& status : statuses) {
    if (status.ok()) {
      ++success_count;
    } else if (status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
      ++unauthenticated_count;
    }
  }
  EXPECT_TRUE((success_count == 1 && unauthenticated_count == 1) ||
              (success_count == 2 && unauthenticated_count == 0));
  if (success_count == 2) {
    EXPECT_EQ(responses[0].refresh_token(), responses[1].refresh_token());
  }
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

TEST(SaslServerTest, RevokeTokenRejectsEmptyToken) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::RevokeTokenRequest request;
  veritas::auth::v1::RevokeTokenResponse response;
  const grpc::Status status = server.RevokeToken(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(SaslServerTest, GetTokenStatusRejectsEmptyToken) {
  SaslServer server(DefaultOptions());
  veritas::auth::v1::GetTokenStatusRequest request;
  veritas::auth::v1::GetTokenStatusResponse response;
  const grpc::Status status = server.GetTokenStatus(request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(SaslServerTest, RevokeTokenUpdatesStatusToRevoked) {
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

  veritas::auth::v1::GetTokenStatusRequest active_request;
  veritas::auth::v1::GetTokenStatusResponse active_response;
  active_request.set_refresh_token(finish_response.refresh_token());
  ASSERT_TRUE(server.GetTokenStatus(active_request, &active_response).ok());
  EXPECT_EQ(active_response.state(),
            veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE);
  EXPECT_FALSE(active_response.user_uuid().empty());

  veritas::auth::v1::RevokeTokenRequest revoke_request;
  veritas::auth::v1::RevokeTokenResponse revoke_response;
  revoke_request.set_refresh_token(finish_response.refresh_token());
  revoke_request.set_reason("test-revoke");
  ASSERT_TRUE(server.RevokeToken(revoke_request, &revoke_response).ok());
  EXPECT_TRUE(revoke_response.revoked());

  veritas::auth::v1::GetTokenStatusResponse revoked_response;
  ASSERT_TRUE(server.GetTokenStatus(active_request, &revoked_response).ok());
  EXPECT_EQ(revoked_response.state(),
            veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED);
  EXPECT_EQ(revoked_response.reason(), "test-revoke");
  EXPECT_EQ(revoked_response.user_uuid(), active_response.user_uuid());
}

TEST(SaslServerTest, RotationGraceExpiresOldTokenAfterNewLogin) {
  SaslServerOptions options = DefaultOptions();
  options.token_rotation_grace_ttl = std::chrono::seconds(1);
  SaslServer server(options);

  veritas::auth::v1::BeginAuthRequest begin_one;
  veritas::auth::v1::BeginAuthResponse begin_response_one;
  begin_one.set_login_username("alice");
  ASSERT_TRUE(server.BeginAuth(begin_one, &begin_response_one).ok());

  veritas::auth::v1::FinishAuthRequest finish_one;
  veritas::auth::v1::FinishAuthResponse finish_response_one;
  finish_one.set_session_id(begin_response_one.session_id());
  finish_one.set_client_proof("proof-1");
  ASSERT_TRUE(server.FinishAuth(finish_one, &finish_response_one).ok());

  veritas::auth::v1::BeginAuthRequest begin_two;
  veritas::auth::v1::BeginAuthResponse begin_response_two;
  begin_two.set_login_username("alice");
  ASSERT_TRUE(server.BeginAuth(begin_two, &begin_response_two).ok());

  veritas::auth::v1::FinishAuthRequest finish_two;
  veritas::auth::v1::FinishAuthResponse finish_response_two;
  finish_two.set_session_id(begin_response_two.session_id());
  finish_two.set_client_proof("proof-2");
  ASSERT_TRUE(server.FinishAuth(finish_two, &finish_response_two).ok());
  EXPECT_NE(finish_response_one.refresh_token(), finish_response_two.refresh_token());

  veritas::auth::v1::GetTokenStatusRequest status_request_old;
  veritas::auth::v1::GetTokenStatusResponse status_response_old;
  status_request_old.set_refresh_token(finish_response_one.refresh_token());
  ASSERT_TRUE(server.GetTokenStatus(status_request_old, &status_response_old).ok());
  EXPECT_EQ(status_response_old.state(),
            veritas::auth::v1::TOKEN_STATUS_STATE_ACTIVE);

  std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  veritas::auth::v1::GetTokenStatusResponse status_response_expired;
  ASSERT_TRUE(
      server.GetTokenStatus(status_request_old, &status_response_expired).ok());
  EXPECT_EQ(status_response_expired.state(),
            veritas::auth::v1::TOKEN_STATUS_STATE_REVOKED);
  EXPECT_EQ(status_response_expired.reason(), "rotation-grace-expired");
}

}  // namespace veritas::gatekeeper
