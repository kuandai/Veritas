#pragma once

#include <memory>

#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include "authorizer.h"
#include "notary.grpc.pb.h"
#include "signer.h"
#include "veritas/shared/issuance_store.h"

namespace veritas::notary {

class NotaryServiceImpl final : public veritas::notary::v1::Notary::Service {
 public:
  NotaryServiceImpl(std::shared_ptr<RequestAuthorizer> authorizer,
                    std::shared_ptr<Signer> signer,
                    std::shared_ptr<veritas::shared::IssuanceStore> issuance_store);

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
  std::shared_ptr<Signer> signer_;
  std::shared_ptr<veritas::shared::IssuanceStore> issuance_store_;
};

}  // namespace veritas::notary
