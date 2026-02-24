#include "notary_service.h"

#include <chrono>
#include <memory>
#include <optional>
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
    return next_issue_result_;
  }

  SigningResult Renew(const RenewalSigningRequest& /*request*/) override {
    ++renew_calls_;
    return next_renew_result_;
  }

  void SetNextIssueResult(SigningResult result) {
    next_issue_result_ = std::move(result);
  }

  void SetNextRenewResult(SigningResult result) {
    next_renew_result_ = std::move(result);
  }

  int issue_calls() const { return issue_calls_; }
  int renew_calls() const { return renew_calls_; }

 private:
  SigningResult next_issue_result_;
  SigningResult next_renew_result_;
  int issue_calls_ = 0;
  int renew_calls_ = 0;
};

std::shared_ptr<veritas::shared::IssuanceStore> MakeInMemoryStore() {
  veritas::shared::SharedStoreConfig config;
  config.backend = veritas::shared::SharedStoreBackend::InMemory;
  return veritas::shared::CreateIssuanceStore(config);
}

class ConflictAfterWriteStore final : public veritas::shared::IssuanceStore {
 public:
  explicit ConflictAfterWriteStore(
      std::shared_ptr<veritas::shared::IssuanceStore> delegate)
      : delegate_(std::move(delegate)) {}

  void EnableOnce() { enabled_once_ = true; }

  void PutIssuance(const veritas::shared::IssuanceRecord& record) override {
    if (enabled_once_) {
      enabled_once_ = false;
      delegate_->PutIssuance(record);
      throw veritas::shared::SharedStoreError(
          veritas::shared::SharedStoreError::Kind::Conflict,
          "simulated conflict after write");
    }
    delegate_->PutIssuance(record);
  }

  std::optional<veritas::shared::IssuanceRecord> GetBySerial(
      const std::string& certificate_serial) override {
    return delegate_->GetBySerial(certificate_serial);
  }

  std::optional<veritas::shared::IssuanceRecord> GetByTokenHash(
      const std::string& token_hash) override {
    return delegate_->GetByTokenHash(token_hash);
  }

  bool RegisterIdempotencyKey(const std::string& idempotency_key,
                              const std::string& certificate_serial) override {
    return delegate_->RegisterIdempotencyKey(idempotency_key, certificate_serial);
  }

  std::optional<std::string> ResolveIdempotencyKey(
      const std::string& idempotency_key) override {
    return delegate_->ResolveIdempotencyKey(idempotency_key);
  }

  void Revoke(const std::string& certificate_serial, const std::string& reason,
              const std::string& actor,
              std::chrono::system_clock::time_point revoked_at) override {
    delegate_->Revoke(certificate_serial, reason, actor, revoked_at);
  }

 private:
  std::shared_ptr<veritas::shared::IssuanceStore> delegate_;
  bool enabled_once_ = false;
};

class DenyRateLimiter final : public RateLimiter {
 public:
  bool Allow(std::string_view /*key*/) override { return false; }
};

void SeedIssuedCertificate(NotaryServiceImpl* service, FakeSigner* signer,
                           const std::string& token,
                           const std::string& serial,
                           std::chrono::system_clock::time_point not_before,
                           std::chrono::system_clock::time_point not_after,
                           const std::string& idempotency_key) {
  SigningResult issued;
  issued.certificate_serial = serial;
  issued.certificate_pem = "leaf-" + serial;
  issued.certificate_chain_pem = "chain-" + serial;
  issued.not_before = not_before;
  issued.not_after = not_after;
  signer->SetNextIssueResult(issued);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token(token);
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key(idempotency_key);
  ASSERT_TRUE(service->IssueCertificate(&context, &request, &response).ok());
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

TEST(NotaryServiceTest, IssueCertificateRejectsOversizedPayloads) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  request.set_csr_der(std::string(70 * 1024, 'a'));
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key("idem-1");

  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST);
}

TEST(NotaryServiceTest, IssueCertificateRateLimitingRecordsMetric) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  auto limiter = std::make_shared<DenyRateLimiter>();
  auto metrics = std::make_shared<InMemorySecurityMetrics>();
  NotaryServiceImpl service(authorizer, signer, store, limiter, metrics);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  request.set_csr_der("csr");
  request.set_requested_ttl_seconds(600);
  request.set_idempotency_key("idem-1");

  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_RATE_LIMITED);
  EXPECT_EQ(metrics->Get("rate_limited"), 1U);
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
  signer->SetNextIssueResult(result);

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
  signer->SetNextIssueResult(first_result);

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
  signer->SetNextIssueResult(second_result);

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
  signer->SetNextIssueResult(result);

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

TEST(NotaryServiceTest, RenewCertificateDeniesUnauthorizedRequests) {
  auto denied_authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid"));
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl denied_service(denied_authorizer, signer, store);

  grpc::ServerContext denied_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial");
  renew_request.set_requested_ttl_seconds(600);
  renew_request.set_idempotency_key("idem");
  EXPECT_EQ(
      denied_service
          .RenewCertificate(&denied_context, &renew_request, &renew_response)
          .error_code(),
      grpc::StatusCode::UNAUTHENTICATED);
}

TEST(NotaryServiceTest, RenewCertificateRejectsOutsideOverlapWindow) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::hours(1), "issue-idem");

  grpc::ServerContext renew_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-1");
  renew_request.set_requested_ttl_seconds(600);
  renew_request.set_idempotency_key("renew-idem");

  const auto status =
      service.RenewCertificate(&renew_context, &renew_request, &renew_response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(renew_response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED);
}

TEST(NotaryServiceTest, RenewCertificateSucceedsInsideOverlapWindow) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  SigningResult renewed_result;
  renewed_result.certificate_serial = "serial-2";
  renewed_result.certificate_pem = "leaf-serial-2";
  renewed_result.certificate_chain_pem = "chain-serial-2";
  renewed_result.not_before = now;
  renewed_result.not_after = now + std::chrono::minutes(30);
  signer->SetNextRenewResult(renewed_result);

  grpc::ServerContext renew_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-1");
  renew_request.set_requested_ttl_seconds(1200);
  renew_request.set_idempotency_key("renew-idem");

  const auto status =
      service.RenewCertificate(&renew_context, &renew_request, &renew_response);
  ASSERT_TRUE(status.ok());
  EXPECT_TRUE(renew_response.renewed());
  EXPECT_EQ(renew_response.certificate_serial(), "serial-2");
  EXPECT_EQ(signer->renew_calls(), 1);
}

TEST(NotaryServiceTest, RenewCertificateReplaysIdempotentRequest) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  SigningResult renewed_result;
  renewed_result.certificate_serial = "serial-2";
  renewed_result.certificate_pem = "leaf-serial-2";
  renewed_result.certificate_chain_pem = "chain-serial-2";
  renewed_result.not_before = now;
  renewed_result.not_after = now + std::chrono::minutes(30);
  signer->SetNextRenewResult(renewed_result);

  veritas::notary::v1::RenewCertificateRequest renew_request;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-1");
  renew_request.set_requested_ttl_seconds(1200);
  renew_request.set_idempotency_key("renew-idem");

  grpc::ServerContext first_context;
  veritas::notary::v1::RenewCertificateResponse first_response;
  ASSERT_TRUE(
      service.RenewCertificate(&first_context, &renew_request, &first_response)
          .ok());
  ASSERT_EQ(signer->renew_calls(), 1);

  signer->SetNextRenewResult(SigningResult{
      "leaf-unused", "chain-unused", "unused",
      std::chrono::system_clock::now(),
      std::chrono::system_clock::now() + std::chrono::minutes(5)});

  grpc::ServerContext second_context;
  veritas::notary::v1::RenewCertificateResponse second_response;
  ASSERT_TRUE(
      service.RenewCertificate(&second_context, &renew_request, &second_response)
          .ok());
  EXPECT_EQ(signer->renew_calls(), 1);
  EXPECT_EQ(second_response.certificate_serial(), "serial-2");
}

TEST(NotaryServiceTest, RenewCertificateRecoversFromConflictAfterWrite) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto base_store = MakeInMemoryStore();
  auto flaky_store = std::make_shared<ConflictAfterWriteStore>(base_store);
  NotaryServiceImpl service(authorizer, signer, flaky_store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  SigningResult renewed_result;
  renewed_result.certificate_serial = "serial-2";
  renewed_result.certificate_pem = "leaf-serial-2";
  renewed_result.certificate_chain_pem = "chain-serial-2";
  renewed_result.not_before = now;
  renewed_result.not_after = now + std::chrono::minutes(30);
  signer->SetNextRenewResult(renewed_result);
  flaky_store->EnableOnce();

  grpc::ServerContext renew_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-1");
  renew_request.set_requested_ttl_seconds(1200);
  renew_request.set_idempotency_key("renew-idem");

  const auto status =
      service.RenewCertificate(&renew_context, &renew_request, &renew_response);
  ASSERT_TRUE(status.ok());
  EXPECT_TRUE(renew_response.renewed());
  EXPECT_EQ(renew_response.certificate_serial(), "serial-2");
}

TEST(NotaryServiceTest, RevokeCertificateDeniesUnauthorizedRequests) {
  auto denied_authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid"));
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl denied_service(denied_authorizer, signer, store);

  grpc::ServerContext denied_context_revoke;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse revoke_response;
  revoke_request.set_refresh_token("token");
  revoke_request.set_certificate_serial("serial");
  revoke_request.set_reason("POLICY_VIOLATION");
  revoke_request.set_actor("unit-test");
  EXPECT_EQ(
      denied_service
          .RevokeCertificate(&denied_context_revoke, &revoke_request,
                             &revoke_response)
          .error_code(),
      grpc::StatusCode::UNAUTHENTICATED);
}

TEST(NotaryServiceTest, RevokeCertificateRevokesAndIsIdempotent) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  grpc::ServerContext first_context;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse first_response;
  revoke_request.set_refresh_token("token");
  revoke_request.set_certificate_serial("serial-1");
  revoke_request.set_reason("TOKEN_REVOKED");
  revoke_request.set_actor("incident-response");
  ASSERT_TRUE(
      service.RevokeCertificate(&first_context, &revoke_request, &first_response)
          .ok());
  EXPECT_TRUE(first_response.revoked());

  grpc::ServerContext second_context;
  veritas::notary::v1::RevokeCertificateResponse second_response;
  const auto second_status =
      service.RevokeCertificate(&second_context, &revoke_request, &second_response);
  EXPECT_EQ(second_status.error_code(), grpc::StatusCode::ALREADY_EXISTS);
  EXPECT_EQ(second_response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_ALREADY_REVOKED);
}

TEST(NotaryServiceTest, GetCertificateStatusReturnsLifecycleStates) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "active-serial", now,
                        now + std::chrono::minutes(20), "issue-active");
  SeedIssuedCertificate(&service, signer.get(), "token", "expired-serial",
                        now - std::chrono::minutes(30),
                        now - std::chrono::minutes(1), "issue-expired");
  SeedIssuedCertificate(&service, signer.get(), "token", "revoked-serial", now,
                        now + std::chrono::minutes(20), "issue-revoked");

  grpc::ServerContext revoke_context;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse revoke_response;
  revoke_request.set_refresh_token("token");
  revoke_request.set_certificate_serial("revoked-serial");
  revoke_request.set_reason("TOKEN_REVOKED");
  revoke_request.set_actor("status-test");
  ASSERT_TRUE(
      service.RevokeCertificate(&revoke_context, &revoke_request, &revoke_response)
          .ok());

  grpc::ServerContext active_context;
  veritas::notary::v1::GetCertificateStatusRequest active_request;
  veritas::notary::v1::GetCertificateStatusResponse active_response;
  active_request.set_certificate_serial("active-serial");
  active_request.set_refresh_token("token");
  ASSERT_TRUE(
      service.GetCertificateStatus(&active_context, &active_request,
                                   &active_response)
          .ok());
  EXPECT_EQ(active_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_ACTIVE);

  grpc::ServerContext expired_context;
  veritas::notary::v1::GetCertificateStatusRequest expired_request;
  veritas::notary::v1::GetCertificateStatusResponse expired_response;
  expired_request.set_certificate_serial("expired-serial");
  expired_request.set_refresh_token("token");
  ASSERT_TRUE(
      service.GetCertificateStatus(&expired_context, &expired_request,
                                   &expired_response)
          .ok());
  EXPECT_EQ(expired_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_EXPIRED);

  grpc::ServerContext revoked_context;
  veritas::notary::v1::GetCertificateStatusRequest revoked_request;
  veritas::notary::v1::GetCertificateStatusResponse revoked_response;
  revoked_request.set_certificate_serial("revoked-serial");
  revoked_request.set_refresh_token("token");
  ASSERT_TRUE(
      service.GetCertificateStatus(&revoked_context, &revoked_request,
                                   &revoked_response)
          .ok());
  EXPECT_EQ(revoked_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_REVOKED);
  EXPECT_EQ(revoked_response.reason(), "TOKEN_REVOKED");

  grpc::ServerContext unknown_context;
  veritas::notary::v1::GetCertificateStatusRequest unknown_request;
  veritas::notary::v1::GetCertificateStatusResponse unknown_response;
  unknown_request.set_certificate_serial("missing");
  unknown_request.set_refresh_token("token");
  ASSERT_TRUE(
      service.GetCertificateStatus(&unknown_context, &unknown_request,
                                   &unknown_response)
          .ok());
  EXPECT_EQ(unknown_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNKNOWN);
}

TEST(NotaryServiceTest, RenewalIsRejectedAfterRevocation) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  grpc::ServerContext revoke_context;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse revoke_response;
  revoke_request.set_refresh_token("token");
  revoke_request.set_certificate_serial("serial-1");
  revoke_request.set_reason("TOKEN_REVOKED");
  revoke_request.set_actor("unit-test");
  ASSERT_TRUE(
      service.RevokeCertificate(&revoke_context, &revoke_request, &revoke_response)
          .ok());

  grpc::ServerContext renew_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-1");
  renew_request.set_requested_ttl_seconds(1200);
  renew_request.set_idempotency_key("renew-idem");
  const auto renew_status =
      service.RenewCertificate(&renew_context, &renew_request, &renew_response);
  EXPECT_EQ(renew_status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(renew_response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED);
}

TEST(NotaryServiceTest, RevokeCertificateRejectsMissingActorOrReason) {
  auto allow_authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(allow_authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::RevokeCertificateRequest request;
  veritas::notary::v1::RevokeCertificateResponse response;
  request.set_refresh_token("token");
  request.set_certificate_serial("serial");
  request.set_reason("TOKEN_REVOKED");
  EXPECT_EQ(service.RevokeCertificate(&context, &request, &response).error_code(),
            grpc::StatusCode::INVALID_ARGUMENT);

  grpc::ServerContext context_two;
  veritas::notary::v1::RevokeCertificateRequest request_two;
  veritas::notary::v1::RevokeCertificateResponse response_two;
  request_two.set_refresh_token("token");
  request_two.set_certificate_serial("serial");
  request_two.set_actor("unit-test");
  EXPECT_EQ(
      service.RevokeCertificate(&context_two, &request_two, &response_two)
          .error_code(),
      grpc::StatusCode::INVALID_ARGUMENT);

  grpc::ServerContext context_three;
  veritas::notary::v1::RevokeCertificateRequest request_three;
  veritas::notary::v1::RevokeCertificateResponse response_three;
  request_three.set_refresh_token("token");
  request_three.set_certificate_serial("serial");
  request_three.set_actor("unit-test");
  request_three.set_reason("NOT_A_REAL_REASON");
  EXPECT_EQ(
      service.RevokeCertificate(&context_three, &request_three, &response_three)
          .error_code(),
      grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(NotaryServiceTest, GetCertificateStatusRejectsMissingToken) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::GetCertificateStatusRequest request;
  veritas::notary::v1::GetCertificateStatusResponse response;
  request.set_certificate_serial("serial");
  const auto status = service.GetCertificateStatus(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST);
}

TEST(NotaryServiceTest, GetCertificateStatusDeniesUnauthorizedToken) {
  auto authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid"));
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  grpc::ServerContext context;
  veritas::notary::v1::GetCertificateStatusRequest request;
  veritas::notary::v1::GetCertificateStatusResponse response;
  request.set_certificate_serial("serial");
  request.set_refresh_token("token");
  const auto status = service.GetCertificateStatus(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_INVALID);
}

TEST(NotaryServiceTest, GetCertificateStatusDeniesTokenOwnershipMismatch) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SeedIssuedCertificate(&service, signer.get(), "token-a", "serial-1", now,
                        now + std::chrono::minutes(10), "issue-idem");

  grpc::ServerContext context;
  veritas::notary::v1::GetCertificateStatusRequest request;
  veritas::notary::v1::GetCertificateStatusResponse response;
  request.set_certificate_serial("serial-1");
  request.set_refresh_token("token-b");
  const auto status = service.GetCertificateStatus(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(response.error().code(),
            veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED);
}

TEST(NotaryServiceTest, LifecycleIssueRenewRevokeStatus) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  auto signer = std::make_shared<FakeSigner>();
  auto store = MakeInMemoryStore();
  NotaryServiceImpl service(authorizer, signer, store);

  const auto now = std::chrono::system_clock::now();
  SigningResult issued_result;
  issued_result.certificate_serial = "serial-issue";
  issued_result.certificate_pem = "leaf-issue";
  issued_result.certificate_chain_pem = "chain-issue";
  issued_result.not_before = now;
  issued_result.not_after = now + std::chrono::minutes(10);
  signer->SetNextIssueResult(issued_result);

  grpc::ServerContext issue_context;
  veritas::notary::v1::IssueCertificateRequest issue_request;
  veritas::notary::v1::IssueCertificateResponse issue_response;
  issue_request.set_refresh_token("token");
  issue_request.set_csr_der("csr");
  issue_request.set_requested_ttl_seconds(600);
  issue_request.set_idempotency_key("idem-issue");
  ASSERT_TRUE(
      service.IssueCertificate(&issue_context, &issue_request, &issue_response)
          .ok());
  ASSERT_TRUE(issue_response.issued());
  EXPECT_EQ(issue_response.certificate_serial(), "serial-issue");

  SigningResult renewed_result;
  renewed_result.certificate_serial = "serial-renewed";
  renewed_result.certificate_pem = "leaf-renewed";
  renewed_result.certificate_chain_pem = "chain-renewed";
  renewed_result.not_before = now;
  renewed_result.not_after = now + std::chrono::minutes(30);
  signer->SetNextRenewResult(renewed_result);

  grpc::ServerContext renew_context;
  veritas::notary::v1::RenewCertificateRequest renew_request;
  veritas::notary::v1::RenewCertificateResponse renew_response;
  renew_request.set_refresh_token("token");
  renew_request.set_certificate_serial("serial-issue");
  renew_request.set_requested_ttl_seconds(1200);
  renew_request.set_idempotency_key("idem-renew");
  ASSERT_TRUE(
      service.RenewCertificate(&renew_context, &renew_request, &renew_response)
          .ok());
  ASSERT_TRUE(renew_response.renewed());
  EXPECT_EQ(renew_response.certificate_serial(), "serial-renewed");

  grpc::ServerContext active_status_context;
  veritas::notary::v1::GetCertificateStatusRequest active_status_request;
  veritas::notary::v1::GetCertificateStatusResponse active_status_response;
  active_status_request.set_certificate_serial("serial-renewed");
  active_status_request.set_refresh_token("token");
  ASSERT_TRUE(service.GetCertificateStatus(&active_status_context,
                                           &active_status_request,
                                           &active_status_response)
                  .ok());
  EXPECT_EQ(active_status_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_ACTIVE);

  grpc::ServerContext revoke_context;
  veritas::notary::v1::RevokeCertificateRequest revoke_request;
  veritas::notary::v1::RevokeCertificateResponse revoke_response;
  revoke_request.set_refresh_token("token");
  revoke_request.set_certificate_serial("serial-renewed");
  revoke_request.set_reason("TOKEN_REVOKED");
  revoke_request.set_actor("smoke");
  ASSERT_TRUE(
      service.RevokeCertificate(&revoke_context, &revoke_request, &revoke_response)
          .ok());
  ASSERT_TRUE(revoke_response.revoked());

  grpc::ServerContext revoked_status_context;
  veritas::notary::v1::GetCertificateStatusRequest revoked_status_request;
  veritas::notary::v1::GetCertificateStatusResponse revoked_status_response;
  revoked_status_request.set_certificate_serial("serial-renewed");
  revoked_status_request.set_refresh_token("token");
  ASSERT_TRUE(service.GetCertificateStatus(&revoked_status_context,
                                           &revoked_status_request,
                                           &revoked_status_response)
                  .ok());
  EXPECT_EQ(revoked_status_response.state(),
            veritas::notary::v1::CERTIFICATE_STATUS_STATE_REVOKED);
  EXPECT_EQ(revoked_status_response.reason(), "TOKEN_REVOKED");
}

}  // namespace
}  // namespace veritas::notary
