#include "notary_service.h"

#include <memory>
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

TEST(NotaryServiceTest, IssueCertificateDeniesUnauthorizedRequests) {
  auto authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "denied"));
  NotaryServiceImpl service(authorizer);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(NotaryServiceTest, IssueCertificateReachesPlaceholderWhenAuthorized) {
  auto authorizer = std::make_shared<FixedAuthorizer>(grpc::Status::OK);
  NotaryServiceImpl service(authorizer);

  grpc::ServerContext context;
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token("token");
  const auto status = service.IssueCertificate(&context, &request, &response);
  EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

TEST(NotaryServiceTest, RenewAndRevokeApplyAuthorizationGate) {
  auto denied_authorizer = std::make_shared<FixedAuthorizer>(
      grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid"));
  NotaryServiceImpl denied_service(denied_authorizer);

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
  NotaryServiceImpl allow_service(allow_authorizer);

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
