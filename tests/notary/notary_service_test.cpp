#include "notary_service.h"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

#include <gtest/gtest.h>
#include <grpcpp/server_context.h>

namespace veritas::notary {
namespace {

class FixedAuthorizer final : public RequestAuthorizer {
 public:
  explicit FixedAuthorizer(grpc::Status status) : status_(std::move(status)) {}

  grpc::Status AuthorizeRefreshToken(
      std::string_view /*refresh_token*/) const override {
    return status_;
  }

 private:
  grpc::Status status_;
};

class FakeSigner final : public Signer {
 public:
  SigningResult Issue(const SigningRequest& /*request*/) override {
    ++issue_calls_;
    return next_result_;
  }

  void SetNextResult(SigningResult result) { next_result_ = std::move(result); }

  int issue_calls() const { return issue_calls_; }

 private:
  SigningResult next_result_;
  int issue_calls_ = 0;
};

std::shared_ptr<veritas::shared::IssuanceStore> MakeInMemoryStore() {
  veritas::shared::SharedStoreConfig config;
  config.backend = veritas::shared::SharedStoreBackend::InMemory;
  return veritas::shared::CreateIssuanceStore(config);
}

TEST(NotaryServiceTest, IssueCertificateDeniesUnauthorizedRequests) {
  auto authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "revoked"));
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key("idem-1");

  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED);
  EXPECT_FALSE(response.issued());
}

TEST(NotaryServiceTest, IssueCertificateRejectsInvalidRequest) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(59);
  request.set_idempotency_key("idem-1");

  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST);
  EXPECT_EQ(signer->issue_calls(), 0);
}

TEST(NotaryServiceTest, IssueCertificatePersistsAndReturnsIssuedRecord) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SigningResult result;
  result.certificate_serial = "A1B2C3";
  result.certificate_pem = "leaf-cert";
  result.certificate_chain_pem = "intermediate-chain";
  result.not_before = now;
  result.not_after = now + std::chrono::minutes(10);
  signer->SetNextResult(result);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key("idem-1");

  const auto status = service.IssueCertificate(&context, &request, &response);
  ASSERT_TRUE(status.ok());
  EXPECT_TRUE(response.issued());
  EXPECT_EQ(response.certificate_serial(), "A1B2C3");
  EXPECT_EQ(response.certificate_pem(), "leaf-cert");
  EXPECT_EQ(response.certificate_chain_pem(), "intermediate-chain");
  EXPECT_EQ(signer->issue_calls(), 1);

  const auto serial = store->ResolveIdempotencyKey("idem-1");
  ASSERT_TRUE(serial.has_value());
  EXPECT_EQ(*serial, "A1B2C3");
  const auto persisted = store->GetBySerial("A1B2C3");
  ASSERT_TRUE(persisted.has_value());
  EXPECT_EQ(persisted->certificate_pem, "leaf-cert");
  EXPECT_EQ(persisted->certificate_chain_pem, "intermediate-chain");
}

TEST(NotaryServiceTest, IssueCertificateReplaysIdempotentRequest) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  SigningResult first_result;
  first_result.certificate_serial = "SERIAL-1";
  first_result.certificate_pem = "leaf-1";
  first_result.certificate_chain_pem = "chain-1";
  first_result.not_before = std::chrono::system_clock::now();
  first_result.not_after = first_result.not_before + std::chrono::minutes(5);
  signer->SetNextResult(first_result);

  grpc::ServerContext context_first;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse first_response;
  request.set_refresh_token("token");
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key("idem-1");
  ASSERT_TRUE(
      service.IssueCertificate(&context_first, &request, &first_response).ok());
  ASSERT_EQ(signer->issue_calls(), 1);

  SigningResult second_result;
  second_result.certificate_serial = "SERIAL-2";
  second_result.certificate_pem = "leaf-2";
  second_result.certificate_chain_pem = "chain-2";
  second_result.not_before = std::chrono::system_clock::now();
  second_result.not_after = second_result.not_before + std::chrono::minutes(5);
  signer->SetNextResult(second_result);

  grpc::ServerContext context_replay;
  veritas::notary::v1::IssueCertificateResponse replay_response;
  const auto replay_status =
      service.IssueCertificate(&context_replay, &request, &replay_response);
  ASSERT_TRUE(replay_status.ok());
  EXPECT_EQ(signer->issue_calls(), 1);
  EXPECT_EQ(replay_response.certificate_serial(), "SERIAL-1");
  EXPECT_EQ(replay_response.certificate_pem(), "leaf-1");
}

TEST(NotaryServiceTest, IssueCertificateRejectsIdempotencyTokenMismatch) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  SigningResult result;
  result.certificate_serial = "SERIAL-1";
  result.certificate_pem = "leaf-1";
  result.certificate_chain_pem = "chain-1";
  result.not_before = std::chrono::system_clock::now();
  result.not_after = result.not_before + std::chrono::minutes(5);
  signer->SetNextResult(result);

  grpc::ServerContext first_context;
  veritas::notary::v1::IssueCertificateRequest first_request;
  veritas::notary::v1::IssueCertificateResponse first_response;
  first_request.set_refresh_token("token-a");
  first_request.set_csr_der("csr");
  first_request.set_requested_ttl_seconds(600);
  first_request.set_idempotency_key("idem-1");
  ASSERT_TRUE(service.IssueCertificate(&first_context, &first_request,
                                       &first_response)
                  .ok());

  grpc::ServerContext second_context;
  veritas::notary::v1::IssueCertificateRequest second_request;
  veritas::notary::v1::IssueCertificateResponse second_response;
  second_request.set_refresh_token("token-b");
  second_request.set_csr_der("csr");
  second_request.set_requested_ttl_seconds(600);
  second_request.set_idempotency_key("idem-1");

  const auto status =
      service.IssueCertificate(&second_context, &second_request, &second_response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(second_response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED);
}

TEST(NotaryServiceTest, RenewAndRevokeApplyAuthorizationGate) {
  auto denied_authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid"));
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl denied_service(denied_authorizer, signer, store);

  grpc::ServerContext denied_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  EXPECT_EQ(
      denied_service
          .RenewCertificate(&denied_context, &renew_request, &renew_response)
          .error_code(),
      grpc::StatusCode::UNAUTHENTICATED);

  grpc::ServerContext denied_context_revoke;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse revoke_response;
  revoke_request.set_refresh_token("token");
  EXPECT_EQ(
      denied_service
          .RevokeCertificate(&denied_context_revoke, &revoke_request,
                             &revoke_response)
          .error_code(),
      grpc::StatusCode::UNAUTHENTICATED);

  auto allow_authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  NotaryServiceImpl allow_service(allow_authorizer, signer, store);

  grpc::ServerContext allow_context;
  EXPECT_EQ(
      allow_service
          .RenewCertificate(&allow_context, &renew_request, &renew_response)
          .error_code(),
      grpc::StatusCode::FAILED_PRECONDITION);

  grpc::ServerContext allow_context_revoke;
  EXPECT_EQ(
      allow_service
          .RevokeCertificate(&allow_context_revoke, &revoke_request,
                             &revoke_response)
          .error_code(),
      grpc::StatusCode::FAILED_PRECONDITION);
}

}  // namespace
}  // namespace veritas::notary
