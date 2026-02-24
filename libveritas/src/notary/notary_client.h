#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>

#include "notary.grpc.pb.h"
#include "veritas/identity_manager.h"

namespace veritas::notary_client {

class NotaryClientError : public std::runtime_error {
 public:
  NotaryClientError(grpc::StatusCode transport_code,
                    veritas::notary::v1::NotaryErrorCode service_code,
                    std::string message)
      : std::runtime_error(std::move(message)),
        transport_code_(transport_code),
        service_code_(service_code) {}

  grpc::StatusCode transport_code() const noexcept { return transport_code_; }
  veritas::notary::v1::NotaryErrorCode service_code() const noexcept {
    return service_code_;
  }

 private:
  grpc::StatusCode transport_code_;
  veritas::notary::v1::NotaryErrorCode service_code_;
};

class NotaryClient {
 public:
  explicit NotaryClient(const NotaryClientConfig& config);

  CertificateMaterial IssueCertificate(std::string_view refresh_token,
                                       std::string_view csr_der,
                                       std::uint32_t requested_ttl_seconds,
                                       std::string_view idempotency_key);
  CertificateMaterial RenewCertificate(std::string_view refresh_token,
                                       std::string_view certificate_serial,
                                       std::uint32_t requested_ttl_seconds,
                                       std::string_view idempotency_key);
  void RevokeCertificate(std::string_view refresh_token,
                         std::string_view certificate_serial,
                         std::string_view reason,
                         std::string_view actor);
  CertificateStatusResult GetCertificateStatus(std::string_view refresh_token,
                                               std::string_view certificate_serial);

 private:
  NotaryClientConfig config_;
  std::shared_ptr<grpc::Channel> channel_;
  std::unique_ptr<veritas::notary::v1::Notary::Stub> stub_;
};

}  // namespace veritas::notary_client
