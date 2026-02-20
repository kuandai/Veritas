#include "notary_service.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include <grpcpp/support/status_code_enum.h>

#include "log_utils.h"
#include "token_hash.h"

namespace veritas::notary {
namespace {

constexpr uint32_t kMinIssueTtlSeconds = 60;
constexpr uint32_t kMaxIssueTtlSeconds = 24 * 60 * 60;
constexpr auto kRenewalOverlapWindow = std::chrono::minutes(15);

grpc::Status IssuePipelinePlaceholderStatus() {
  return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                      "notary issuance pipeline is not implemented");
}

void SetError(veritas::notary::v1::NotaryErrorDetail* error,
              veritas::notary::v1::NotaryErrorCode code,
              std::string_view detail) {
  error->set_code(code);
  error->set_detail(std::string(detail));
}

grpc::StatusCode TransportStatusForNotaryCode(
    veritas::notary::v1::NotaryErrorCode code) {
  using veritas::notary::v1::NotaryErrorCode;
  switch (code) {
    case NotaryErrorCode::NOTARY_ERROR_CODE_INVALID_REQUEST:
      return grpc::StatusCode::INVALID_ARGUMENT;
    case NotaryErrorCode::NOTARY_ERROR_CODE_UNAUTHORIZED:
    case NotaryErrorCode::NOTARY_ERROR_CODE_TOKEN_INVALID:
    case NotaryErrorCode::NOTARY_ERROR_CODE_TOKEN_EXPIRED:
      return grpc::StatusCode::UNAUTHENTICATED;
    case NotaryErrorCode::NOTARY_ERROR_CODE_TOKEN_REVOKED:
    case NotaryErrorCode::NOTARY_ERROR_CODE_POLICY_DENIED:
      return grpc::StatusCode::PERMISSION_DENIED;
    case NotaryErrorCode::NOTARY_ERROR_CODE_ALREADY_REVOKED:
      return grpc::StatusCode::ALREADY_EXISTS;
    case NotaryErrorCode::NOTARY_ERROR_CODE_RATE_LIMITED:
      return grpc::StatusCode::RESOURCE_EXHAUSTED;
    case NotaryErrorCode::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE:
      return grpc::StatusCode::UNAVAILABLE;
    case NotaryErrorCode::NOTARY_ERROR_CODE_INTERNAL:
    case NotaryErrorCode::NOTARY_ERROR_CODE_UNSPECIFIED:
    default:
      return grpc::StatusCode::INTERNAL;
  }
}

grpc::Status StatusWithNotaryError(
    veritas::notary::v1::IssueCertificateResponse* response,
    veritas::notary::v1::NotaryErrorCode code, std::string_view detail) {
  SetError(response->mutable_error(), code, detail);
  return grpc::Status(TransportStatusForNotaryCode(code), std::string(detail));
}

grpc::Status StatusWithNotaryError(
    veritas::notary::v1::RenewCertificateResponse* response,
    veritas::notary::v1::NotaryErrorCode code, std::string_view detail) {
  SetError(response->mutable_error(), code, detail);
  return grpc::Status(TransportStatusForNotaryCode(code), std::string(detail));
}

void FillTimestamp(
    std::chrono::system_clock::time_point tp,
    google::protobuf::Timestamp* timestamp) {
  const auto since_epoch = tp.time_since_epoch();
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
      since_epoch - seconds);
  timestamp->set_seconds(seconds.count());
  timestamp->set_nanos(static_cast<int32_t>(nanos.count()));
}

void FillIssuedResponseFromRecord(
    const veritas::shared::IssuanceRecord& record,
    veritas::notary::v1::IssueCertificateResponse* response) {
  response->set_issued(true);
  response->set_certificate_serial(record.certificate_serial);
  response->set_certificate_pem(record.certificate_pem);
  response->set_certificate_chain_pem(record.certificate_chain_pem);
  FillTimestamp(record.issued_at, response->mutable_not_before());
  FillTimestamp(record.expires_at, response->mutable_not_after());
}

void FillRenewedResponseFromRecord(
    const veritas::shared::IssuanceRecord& record,
    veritas::notary::v1::RenewCertificateResponse* response) {
  response->set_renewed(true);
  response->set_certificate_serial(record.certificate_serial);
  response->set_certificate_pem(record.certificate_pem);
  response->set_certificate_chain_pem(record.certificate_chain_pem);
  FillTimestamp(record.issued_at, response->mutable_not_before());
  FillTimestamp(record.expires_at, response->mutable_not_after());
}

grpc::Status MapStoreErrorToIssueStatus(
    const veritas::shared::SharedStoreError& error,
    veritas::notary::v1::IssueCertificateResponse* response) {
  using Kind = veritas::shared::SharedStoreError::Kind;
  switch (error.kind()) {
    case Kind::InvalidArgument:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
          error.what());
    case Kind::Conflict:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
          error.what());
    case Kind::NotFound:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL,
          error.what());
    case Kind::Unavailable:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE,
          error.what());
    default:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL,
          "shared store returned an unknown failure");
  }
}

grpc::Status MapStoreErrorToRenewStatus(
    const veritas::shared::SharedStoreError& error,
    veritas::notary::v1::RenewCertificateResponse* response) {
  using Kind = veritas::shared::SharedStoreError::Kind;
  switch (error.kind()) {
    case Kind::InvalidArgument:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
          error.what());
    case Kind::Conflict:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
          error.what());
    case Kind::NotFound:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
          error.what());
    case Kind::Unavailable:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE,
          error.what());
    default:
      return StatusWithNotaryError(
          response,
          veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL,
          "shared store returned an unknown failure");
  }
}

grpc::Status MapAuthzStatusToIssueStatus(
    const grpc::Status& status,
    veritas::notary::v1::IssueCertificateResponse* response) {
  if (status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED,
        "refresh token is revoked");
  }
  if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
    return StatusWithNotaryError(
        response,
        veritas::notary::v1::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE,
        "gatekeeper is unavailable");
  }
  if (status.error_code() == grpc::StatusCode::INVALID_ARGUMENT ||
      status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_INVALID,
        "refresh token is invalid");
  }
  return StatusWithNotaryError(
      response, veritas::notary::v1::NOTARY_ERROR_CODE_UNAUTHORIZED,
      "authorization failed");
}

grpc::Status MapAuthzStatusToRenewStatus(
    const grpc::Status& status,
    veritas::notary::v1::RenewCertificateResponse* response) {
  if (status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED,
        "refresh token is revoked");
  }
  if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
    return StatusWithNotaryError(
        response,
        veritas::notary::v1::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE,
        "gatekeeper is unavailable");
  }
  if (status.error_code() == grpc::StatusCode::INVALID_ARGUMENT ||
      status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_INVALID,
        "refresh token is invalid");
  }
  return StatusWithNotaryError(
      response, veritas::notary::v1::NOTARY_ERROR_CODE_UNAUTHORIZED,
      "authorization failed");
}

grpc::Status ValidateIssueRequest(
    const veritas::notary::v1::IssueCertificateRequest& request,
    veritas::notary::v1::IssueCertificateResponse* response,
    std::chrono::seconds* effective_ttl) {
  if (request.refresh_token().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "refresh_token is required");
  }
  if (request.csr_der().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "csr_der is required");
  }
  if (request.idempotency_key().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "idempotency_key is required");
  }

  if (request.requested_ttl_seconds() < kMinIssueTtlSeconds) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "requested_ttl_seconds is below minimum policy bound");
  }

  const auto bounded_ttl = std::min(request.requested_ttl_seconds(),
                                    kMaxIssueTtlSeconds);
  *effective_ttl = std::chrono::seconds(bounded_ttl);
  return grpc::Status::OK;
}

grpc::Status ValidateRenewRequest(
    const veritas::notary::v1::RenewCertificateRequest& request,
    veritas::notary::v1::RenewCertificateResponse* response,
    std::chrono::seconds* effective_ttl) {
  if (request.refresh_token().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "refresh_token is required");
  }
  if (request.certificate_serial().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "certificate_serial is required");
  }
  if (request.idempotency_key().empty()) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "idempotency_key is required");
  }
  if (request.requested_ttl_seconds() < kMinIssueTtlSeconds) {
    return StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "requested_ttl_seconds is below minimum policy bound");
  }

  const auto bounded_ttl = std::min(request.requested_ttl_seconds(),
                                    kMaxIssueTtlSeconds);
  *effective_ttl = std::chrono::seconds(bounded_ttl);
  return grpc::Status::OK;
}

std::string DeriveSubjectMarker(const std::string& token_hash) {
  constexpr size_t kPrefixLength = 16;
  const auto length = std::min(kPrefixLength, token_hash.size());
  return "token:" + token_hash.substr(0, length);
}

}  // namespace

NotaryServiceImpl::NotaryServiceImpl(
    std::shared_ptr<RequestAuthorizer> authorizer, std::shared_ptr<Signer> signer,
    std::shared_ptr<veritas::shared::IssuanceStore> issuance_store)
    : authorizer_(std::move(authorizer)),
      signer_(std::move(signer)),
      issuance_store_(std::move(issuance_store)) {
  if (!authorizer_) {
    throw std::runtime_error("notary authorizer is required");
  }
  if (!signer_) {
    throw std::runtime_error("notary signer is required");
  }
  if (!issuance_store_) {
    throw std::runtime_error("notary issuance store is required");
  }
}

grpc::Status NotaryServiceImpl::IssueCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::IssueCertificateRequest* request,
    veritas::notary::v1::IssueCertificateResponse* response) {
  std::chrono::seconds requested_ttl{};
  const auto validation_status =
      ValidateIssueRequest(*request, response, &requested_ttl);
  if (!validation_status.ok()) {
    LogNotaryEvent("IssueCertificate", validation_status, "validation_failed");
    return validation_status;
  }

  const auto authz = authorizer_->AuthorizeRefreshToken(request->refresh_token());
  if (!authz.ok()) {
    const auto mapped = MapAuthzStatusToIssueStatus(authz, response);
    LogNotaryEvent("IssueCertificate", mapped, "authorization_failed");
    return mapped;
  }

  std::string token_hash;
  try {
    token_hash = HashTokenSha256(request->refresh_token());
  } catch (const std::exception& ex) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
    LogNotaryEvent("IssueCertificate", status, "token_hash_failed");
    return status;
  }

  try {
    const auto existing_serial =
        issuance_store_->ResolveIdempotencyKey(request->idempotency_key());
    if (existing_serial.has_value()) {
      const auto existing_record = issuance_store_->GetBySerial(*existing_serial);
      if (!existing_record.has_value()) {
        const auto status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL,
            "idempotency key references unknown issuance record");
        LogNotaryEvent("IssueCertificate", status, "idempotency_dangling");
        return status;
      }
      if (existing_record->token_hash != token_hash) {
        const auto status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
            "idempotency key is already bound to another token");
        LogNotaryEvent("IssueCertificate", status, "idempotency_conflict");
        return status;
      }
      FillIssuedResponseFromRecord(*existing_record, response);
      LogNotaryEvent("IssueCertificate", grpc::Status::OK, "idempotent_replay");
      return grpc::Status::OK;
    }
  } catch (const veritas::shared::SharedStoreError& ex) {
    const auto status = MapStoreErrorToIssueStatus(ex, response);
    LogNotaryEvent("IssueCertificate", status, "idempotency_lookup_failed");
    return status;
  }

  SigningResult signing_result;
  try {
    SigningRequest signing_request;
    signing_request.csr_der = request->csr_der();
    signing_request.requested_ttl = requested_ttl;
    signing_result = signer_->Issue(signing_request);
  } catch (const SignerIssueError& ex) {
    grpc::Status status;
    switch (ex.code()) {
      case SignerIssueErrorCode::InvalidRequest:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
            ex.what());
        break;
      case SignerIssueErrorCode::PolicyDenied:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
            ex.what());
        break;
      case SignerIssueErrorCode::Internal:
      default:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
        break;
    }
    LogNotaryEvent("IssueCertificate", status, "signer_rejected");
    return status;
  } catch (const std::exception& ex) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
    LogNotaryEvent("IssueCertificate", status, "signer_exception");
    return status;
  }

  veritas::shared::IssuanceRecord record;
  record.certificate_serial = signing_result.certificate_serial;
  record.certificate_pem = signing_result.certificate_pem;
  record.certificate_chain_pem = signing_result.certificate_chain_pem;
  record.user_uuid = DeriveSubjectMarker(token_hash);
  record.token_hash = token_hash;
  record.idempotency_key = request->idempotency_key();
  record.issued_at = signing_result.not_before;
  record.expires_at = signing_result.not_after;
  record.state = veritas::shared::IssuanceState::Active;

  try {
    issuance_store_->PutIssuance(record);
  } catch (const veritas::shared::SharedStoreError& ex) {
    if (ex.kind() == veritas::shared::SharedStoreError::Kind::Conflict) {
      try {
        const auto existing_serial =
            issuance_store_->ResolveIdempotencyKey(request->idempotency_key());
        if (existing_serial.has_value()) {
          const auto existing_record =
              issuance_store_->GetBySerial(*existing_serial);
          if (existing_record.has_value() &&
              existing_record->token_hash == token_hash) {
            FillIssuedResponseFromRecord(*existing_record, response);
            LogNotaryEvent("IssueCertificate", grpc::Status::OK,
                           "idempotent_replay_after_conflict");
            return grpc::Status::OK;
          }
        }
      } catch (const veritas::shared::SharedStoreError&) {
      }
    }
    const auto status = MapStoreErrorToIssueStatus(ex, response);
    LogNotaryEvent("IssueCertificate", status, "issuance_store_failed");
    return status;
  }

  FillIssuedResponseFromRecord(record, response);
  LogNotaryEvent("IssueCertificate", grpc::Status::OK, "issued");
  return grpc::Status::OK;
}

grpc::Status NotaryServiceImpl::RenewCertificate(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::RenewCertificateRequest* request,
    veritas::notary::v1::RenewCertificateResponse* response) {
  std::chrono::seconds requested_ttl{};
  const auto validation_status =
      ValidateRenewRequest(*request, response, &requested_ttl);
  if (!validation_status.ok()) {
    LogNotaryEvent("RenewCertificate", validation_status, "validation_failed");
    return validation_status;
  }

  const auto authz = authorizer_->AuthorizeRefreshToken(request->refresh_token());
  if (!authz.ok()) {
    const auto mapped = MapAuthzStatusToRenewStatus(authz, response);
    LogNotaryEvent("RenewCertificate", mapped, "authorization_failed");
    return mapped;
  }

  std::string token_hash;
  try {
    token_hash = HashTokenSha256(request->refresh_token());
  } catch (const std::exception& ex) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
    LogNotaryEvent("RenewCertificate", status, "token_hash_failed");
    return status;
  }

  try {
    const auto existing_serial =
        issuance_store_->ResolveIdempotencyKey(request->idempotency_key());
    if (existing_serial.has_value()) {
      const auto existing_record = issuance_store_->GetBySerial(*existing_serial);
      if (!existing_record.has_value()) {
        const auto status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL,
            "idempotency key references unknown issuance record");
        LogNotaryEvent("RenewCertificate", status, "idempotency_dangling");
        return status;
      }
      if (existing_record->token_hash != token_hash) {
        const auto status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
            "idempotency key is already bound to another token");
        LogNotaryEvent("RenewCertificate", status, "idempotency_conflict");
        return status;
      }
      FillRenewedResponseFromRecord(*existing_record, response);
      LogNotaryEvent("RenewCertificate", grpc::Status::OK, "idempotent_replay");
      return grpc::Status::OK;
    }
  } catch (const veritas::shared::SharedStoreError& ex) {
    const auto status = MapStoreErrorToRenewStatus(ex, response);
    LogNotaryEvent("RenewCertificate", status, "idempotency_lookup_failed");
    return status;
  }

  std::optional<veritas::shared::IssuanceRecord> current_record;
  try {
    current_record = issuance_store_->GetBySerial(request->certificate_serial());
  } catch (const veritas::shared::SharedStoreError& ex) {
    const auto status = MapStoreErrorToRenewStatus(ex, response);
    LogNotaryEvent("RenewCertificate", status, "issuance_lookup_failed");
    return status;
  }

  if (!current_record.has_value()) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
        "certificate_serial does not exist");
    LogNotaryEvent("RenewCertificate", status, "unknown_serial");
    return status;
  }
  if (current_record->token_hash != token_hash) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
        "certificate does not belong to this token");
    LogNotaryEvent("RenewCertificate", status, "token_mismatch");
    return status;
  }
  if (current_record->state == veritas::shared::IssuanceState::Revoked) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED,
        "certificate is revoked");
    LogNotaryEvent("RenewCertificate", status, "certificate_revoked");
    return status;
  }

  const auto now = std::chrono::system_clock::now();
  if (current_record->expires_at <= now) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_EXPIRED,
        "certificate is expired");
    LogNotaryEvent("RenewCertificate", status, "certificate_expired");
    return status;
  }
  if (current_record->expires_at > now + kRenewalOverlapWindow) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
        "renewal request is outside overlap window");
    LogNotaryEvent("RenewCertificate", status, "outside_overlap_window");
    return status;
  }

  SigningResult signing_result;
  try {
    RenewalSigningRequest renewal_request;
    renewal_request.certificate_pem = current_record->certificate_pem;
    renewal_request.requested_ttl = requested_ttl;
    signing_result = signer_->Renew(renewal_request);
  } catch (const SignerIssueError& ex) {
    grpc::Status status;
    switch (ex.code()) {
      case SignerIssueErrorCode::InvalidRequest:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST,
            ex.what());
        break;
      case SignerIssueErrorCode::PolicyDenied:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED,
            ex.what());
        break;
      case SignerIssueErrorCode::Internal:
      default:
        status = StatusWithNotaryError(
            response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
        break;
    }
    LogNotaryEvent("RenewCertificate", status, "signer_rejected");
    return status;
  } catch (const std::exception& ex) {
    const auto status = StatusWithNotaryError(
        response, veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL, ex.what());
    LogNotaryEvent("RenewCertificate", status, "signer_exception");
    return status;
  }

  veritas::shared::IssuanceRecord renewed_record;
  renewed_record.certificate_serial = signing_result.certificate_serial;
  renewed_record.certificate_pem = signing_result.certificate_pem;
  renewed_record.certificate_chain_pem = signing_result.certificate_chain_pem;
  renewed_record.user_uuid = current_record->user_uuid;
  renewed_record.token_hash = token_hash;
  renewed_record.idempotency_key = request->idempotency_key();
  renewed_record.issued_at = signing_result.not_before;
  renewed_record.expires_at = signing_result.not_after;
  renewed_record.state = veritas::shared::IssuanceState::Active;

  try {
    issuance_store_->PutIssuance(renewed_record);
  } catch (const veritas::shared::SharedStoreError& ex) {
    if (ex.kind() == veritas::shared::SharedStoreError::Kind::Conflict) {
      try {
        const auto existing_serial =
            issuance_store_->ResolveIdempotencyKey(request->idempotency_key());
        if (existing_serial.has_value()) {
          const auto existing_record =
              issuance_store_->GetBySerial(*existing_serial);
          if (existing_record.has_value() &&
              existing_record->token_hash == token_hash) {
            FillRenewedResponseFromRecord(*existing_record, response);
            LogNotaryEvent("RenewCertificate", grpc::Status::OK,
                           "idempotent_replay_after_conflict");
            return grpc::Status::OK;
          }
        }
      } catch (const veritas::shared::SharedStoreError&) {
      }
    }
    const auto status = MapStoreErrorToRenewStatus(ex, response);
    LogNotaryEvent("RenewCertificate", status, "renew_store_failed");
    return status;
  }

  FillRenewedResponseFromRecord(renewed_record, response);
  LogNotaryEvent("RenewCertificate", grpc::Status::OK, "renewed");
  return grpc::Status::OK;
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
  const auto status = IssuePipelinePlaceholderStatus();
  LogNotaryEvent("RevokeCertificate", status, "");
  return status;
}

grpc::Status NotaryServiceImpl::GetCertificateStatus(
    grpc::ServerContext* /*context*/,
    const veritas::notary::v1::GetCertificateStatusRequest* /*request*/,
    veritas::notary::v1::GetCertificateStatusResponse* /*response*/) {
  const auto status = IssuePipelinePlaceholderStatus();
  LogNotaryEvent("GetCertificateStatus", status, "");
  return status;
}

}  // namespace veritas::notary
