#include "notary_service.h"

#include <stdexcept>

#include <grpcpp/support/status_code_enum.h>

#include "log_utils.h"

namespace veritas::notary {
namespace {

grpc::Status UnimplementedStatus() {
  return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                      "notary issuance pipeline is not implemented");
}

}  // namespace

NotaryServiceImpl::NotaryServiceImpl(
    std::shared_ptr<RequestAuthorizer> authorizer)
    : authorizer_(std::move(authorizer)) {
  if (!authorizer_) {
    throw std::runtime_error("notary authorizer is required");
  }
}

grpc::Status NotaryServiceImpl::IssueCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::IssueCertificateRequest* request,
    veritas::notary::v1::IssueCertificateResponse* /*response*/) {
  const auto authz = authorizer_->AuthorizeRefreshToken(request->refresh_token());
  if (!authz.ok()) {
    LogNotaryEvent("IssueCertificate", authz, "authorization_failed");
    return authz;
  }
  const auto status = UnimplementedStatus();
  LogNotaryEvent("IssueCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::RenewCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::RenewCertificateRequest* request,
    veritas::notary::v1::RenewCertificateResponse* /*response*/) {
  const auto authz = authorizer_->AuthorizeRefreshToken(request->refresh_token());
  if (!authz.ok()) {
    LogNotaryEvent("RenewCertificate", authz, "authorization_failed");
    return authz;
  }
  const auto status = UnimplementedStatus();
  LogNotaryEvent("RenewCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::RevokeCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::RevokeCertificateRequest* request,
    veritas::notary::v1::RevokeCertificateResponse* /*response*/) {
  const auto authz = authorizer_->AuthorizeRefreshToken(request->refresh_token());
  if (!authz.ok()) {
    LogNotaryEvent("RevokeCertificate", authz, "authorization_failed");
    return authz;
  }
  const auto status = UnimplementedStatus();
  LogNotaryEvent("RevokeCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::GetCertificateStatus(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::GetCertificateStatusRequest* /*request*/,
    veritas::notary::v1::GetCertificateStatusResponse* /*response*/) {
  const auto status = UnimplementedStatus();
  LogNotaryEvent("GetCertificateStatus", status, "");
  return status;
}

}  // namespace veritas::notary
