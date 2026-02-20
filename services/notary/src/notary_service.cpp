#include "notary_service.h"

#include <grpcpp/support/status_code_enum.h>

#include "log_utils.h"

namespace veritas::notary {
namespace {

grpc::Status UnimplementedStatus() {
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                      "notary behavior is not implemented");
}

}  // namespace

grpc::Status NotaryServiceImpl::IssueCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::IssueCertificateRequest* /*request*/,
    veritas::notary::v1::IssueCertificateResponse* /*response*/) {
  const auto status = UnimplementedStatus();
  LogNotaryEvent("IssueCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::RenewCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::RenewCertificateRequest* /*request*/,
    veritas::notary::v1::RenewCertificateResponse* /*response*/) {
  const auto status = UnimplementedStatus();
  LogNotaryEvent("RenewCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::RevokeCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::RevokeCertificateRequest* /*request*/,
    veritas::notary::v1::RevokeCertificateResponse* /*response*/) {
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
