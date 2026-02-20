#pragma once

#include <memory>

#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include "authorizer.h"
#include "notary.grpc.pb.h"

namespace veritas::notary {

class NotaryServiceImpl final : public veritas::notary::v1::Notary::Service {
 public:
  explicit NotaryServiceImpl(std::shared_ptr<RequestAuthorizer> authorizer);

  grpc::Status IssueCertificate(
      grpc::ServerContext* context,
      const veritas::notary::v1::IssueCertificateRequest* request,
      veritas::notary::v1::IssueCertificateResponse* response) override;
  grpc::Status RenewCertificate(
      grpc::ServerContext* context,
      const veritas::notary::v1::RenewCertificateRequest* request,
      veritas::notary::v1::RenewCertificateResponse* response) override;
  grpc::Status RevokeCertificate(
      grpc::ServerContext* context,
      const veritas::notary::v1::RevokeCertificateRequest* request,
      veritas::notary::v1::RevokeCertificateResponse* response) override;
  grpc::Status GetCertificateStatus(
      grpc::ServerContext* context,
      const veritas::notary::v1::GetCertificateStatusRequest* request,
      veritas::notary::v1::GetCertificateStatusResponse* response) override;

 private:
  std::shared_ptr<RequestAuthorizer> authorizer_;
};

}  // namespace veritas::notary
