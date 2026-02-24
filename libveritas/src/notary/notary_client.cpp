#include "notary_client.h"

#include <chrono>
#include <stdexcept>

namespace veritas::notary_client {
namespace {

constexpr std::string_view kProtocolMetadataKey = "x-veritas-protocol";

std::shared_ptr<grpc::ChannelCredentials> BuildCredentials(
    const NotaryClientConfig& config) {
  if (!config.root_cert_pem.empty()) {
    grpc::SslCredentialsOptions options;
    options.pem_root_certs = config.root_cert_pem;
    return grpc::SslCredentials(options);
  }
  if (config.allow_insecure) {
#if defined(NDEBUG)
    throw std::runtime_error(
        "Insecure Notary transport is disabled in release builds");
#else
    return grpc::InsecureChannelCredentials();
#endif
  }
  throw std::runtime_error("Notary root certificate is required");
}

std::string FormatProtocolVersion(std::uint32_t major, std::uint32_t minor) {
  return std::to_string(major) + "." + std::to_string(minor);
}

void AttachProtocolMetadata(grpc::ClientContext* context,
                            const NotaryClientConfig& config) {
  if (!context) {
    return;
  }
  context->AddMetadata(std::string(kProtocolMetadataKey),
                       FormatProtocolVersion(config.protocol_major,
                                             config.protocol_minor));
}

std::chrono::system_clock::time_point FromTimestamp(
    const google::protobuf::Timestamp& timestamp) {
  return std::chrono::system_clock::time_point(
      std::chrono::seconds(timestamp.seconds()));
}

void ThrowTransportError(const grpc::Status& status,
                         veritas::notary::v1::NotaryErrorCode service_code,
                         std::string_view operation) {
  throw NotaryClientError(
      status.error_code(), service_code,
      std::string(operation) + " failed: " + status.error_message());
}

void ThrowServiceError(veritas::notary::v1::NotaryErrorCode service_code,
                       std::string_view detail,
                       std::string_view operation) {
  throw NotaryClientError(
      grpc::StatusCode::UNKNOWN, service_code,
      std::string(operation) + " failed: " + std::string(detail));
}

}  // namespace

NotaryClient::NotaryClient(const NotaryClientConfig& config) : config_(config) {
  if (config.target.empty()) {
    throw std::runtime_error("Notary target is required");
  }
  channel_ = grpc::CreateChannel(config.target, BuildCredentials(config));
  stub_ = veritas::notary::v1::Notary::NewStub(channel_);
}

CertificateMaterial NotaryClient::IssueCertificate(
    std::string_view refresh_token, std::string_view csr_der,
    std::uint32_t requested_ttl_seconds, std::string_view idempotency_key) {
  veritas::notary::v1::IssueCertificateRequest request;
  veritas::notary::v1::IssueCertificateResponse response;
  request.set_refresh_token(refresh_token.data(), refresh_token.size());
  request.set_csr_der(csr_der.data(), csr_der.size());
  request.set_requested_ttl_seconds(requested_ttl_seconds);
  request.set_idempotency_key(std::string(idempotency_key));

  grpc::ClientContext context;
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->IssueCertificate(&context, request, &response);
  if (!status.ok()) {
    ThrowTransportError(status, response.error().code(), "IssueCertificate");
  }
  if (!response.issued()) {
    ThrowServiceError(response.error().code(), response.error().detail(),
                      "IssueCertificate");
  }

  CertificateMaterial result;
  result.certificate_serial = response.certificate_serial();
  result.certificate_pem = response.certificate_pem();
  result.certificate_chain_pem = response.certificate_chain_pem();
  if (response.has_not_before()) {
    result.not_before = FromTimestamp(response.not_before());
  }
  if (response.has_not_after()) {
    result.not_after = FromTimestamp(response.not_after());
  }
  return result;
}

CertificateMaterial NotaryClient::RenewCertificate(
    std::string_view refresh_token, std::string_view certificate_serial,
    std::uint32_t requested_ttl_seconds, std::string_view idempotency_key) {
  veritas::notary::v1::RenewCertificateRequest request;
  veritas::notary::v1::RenewCertificateResponse response;
  request.set_refresh_token(refresh_token.data(), refresh_token.size());
  request.set_certificate_serial(certificate_serial.data(),
                                 certificate_serial.size());
  request.set_requested_ttl_seconds(requested_ttl_seconds);
  request.set_idempotency_key(std::string(idempotency_key));

  grpc::ClientContext context;
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->RenewCertificate(&context, request, &response);
  if (!status.ok()) {
    ThrowTransportError(status, response.error().code(), "RenewCertificate");
  }
  if (!response.renewed()) {
    ThrowServiceError(response.error().code(), response.error().detail(),
                      "RenewCertificate");
  }

  CertificateMaterial result;
  result.certificate_serial = response.certificate_serial();
  result.certificate_pem = response.certificate_pem();
  result.certificate_chain_pem = response.certificate_chain_pem();
  if (response.has_not_before()) {
    result.not_before = FromTimestamp(response.not_before());
  }
  if (response.has_not_after()) {
    result.not_after = FromTimestamp(response.not_after());
  }
  return result;
}

void NotaryClient::RevokeCertificate(std::string_view refresh_token,
                                     std::string_view certificate_serial,
                                     std::string_view reason,
                                     std::string_view actor) {
  veritas::notary::v1::RevokeCertificateRequest request;
  veritas::notary::v1::RevokeCertificateResponse response;
  request.set_refresh_token(refresh_token.data(), refresh_token.size());
  request.set_certificate_serial(certificate_serial.data(),
                                 certificate_serial.size());
  request.set_reason(std::string(reason));
  request.set_actor(std::string(actor));

  grpc::ClientContext context;
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status = stub_->RevokeCertificate(&context, request, &response);
  if (!status.ok()) {
    ThrowTransportError(status, response.error().code(), "RevokeCertificate");
  }
  if (!response.revoked()) {
    ThrowServiceError(response.error().code(), response.error().detail(),
                      "RevokeCertificate");
  }
}

CertificateStatusResult NotaryClient::GetCertificateStatus(
    std::string_view refresh_token, std::string_view certificate_serial) {
  veritas::notary::v1::GetCertificateStatusRequest request;
  veritas::notary::v1::GetCertificateStatusResponse response;
  request.set_refresh_token(refresh_token.data(), refresh_token.size());
  request.set_certificate_serial(certificate_serial.data(),
                                 certificate_serial.size());

  grpc::ClientContext context;
  AttachProtocolMetadata(&context, config_);
  const grpc::Status status =
      stub_->GetCertificateStatus(&context, request, &response);
  if (!status.ok()) {
    ThrowTransportError(status, response.error().code(), "GetCertificateStatus");
  }

  CertificateStatusResult result;
  switch (response.state()) {
    case veritas::notary::v1::CERTIFICATE_STATUS_STATE_ACTIVE:
      result.state = CertificateStatusState::Active;
      break;
    case veritas::notary::v1::CERTIFICATE_STATUS_STATE_REVOKED:
      result.state = CertificateStatusState::Revoked;
      break;
    case veritas::notary::v1::CERTIFICATE_STATUS_STATE_EXPIRED:
      result.state = CertificateStatusState::Expired;
      break;
    case veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNKNOWN:
    case veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNSPECIFIED:
    default:
      result.state = CertificateStatusState::Unknown;
      break;
  }
  result.reason = response.reason();
  if (response.has_not_before()) {
    result.not_before = FromTimestamp(response.not_before());
  }
  if (response.has_not_after()) {
    result.not_after = FromTimestamp(response.not_after());
  }
  if (response.has_revoked_at()) {
    result.revoked_at = FromTimestamp(response.revoked_at());
  }
  return result;
}

}  // namespace veritas::notary_client
