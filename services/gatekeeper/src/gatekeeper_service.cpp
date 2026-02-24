#include "gatekeeper_service.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>
#include <utility>

#include "log_utils.h"

namespace veritas::auth::v1 {

namespace {

constexpr std::string_view kProtocolMetadataKey = "x-veritas-protocol";
constexpr std::string_view kSelectedProtocolMetadataKey =
    "x-veritas-protocol-selected";
constexpr std::uint32_t kSupportedProtocolMajor = 1;
constexpr std::uint32_t kSupportedProtocolMinor = 0;

std::string ExtractPeerIp(const grpc::ServerContext* context) {
  if (!context) {
    return "unknown";
  }
  const std::string peer = context->peer();
  if (peer.rfind("ipv4:", 0) == 0) {
    const std::string hostport = peer.substr(5);
    const auto colon = hostport.rfind(':');
    if (colon == std::string::npos) {
      return hostport;
    }
    return hostport.substr(0, colon);
  }
  if (peer.rfind("ipv6:", 0) == 0) {
    const std::string hostport = peer.substr(5);
    if (!hostport.empty() && hostport.front() == '[') {
      const auto close = hostport.find(']');
      if (close != std::string::npos && close > 1) {
        return hostport.substr(1, close - 1);
      }
    }
    const auto colon = hostport.rfind(':');
    if (colon == std::string::npos) {
      return hostport;
    }
    return hostport.substr(0, colon);
  }
  return "unknown";
}

std::string FormatProtocolVersion(std::uint32_t major, std::uint32_t minor) {
  return std::to_string(major) + "." + std::to_string(minor);
}

bool ParseProtocolVersion(std::string_view value,
                          std::uint32_t* major,
                          std::uint32_t* minor) {
  if (!major || !minor) {
    return false;
  }
  const auto dot = value.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= value.size()) {
    return false;
  }
  const std::string_view major_part = value.substr(0, dot);
  const std::string_view minor_part = value.substr(dot + 1);
  for (const char ch : major_part) {
    if (!std::isdigit(static_cast<unsigned char>(ch))) {
      return false;
    }
  }
  for (const char ch : minor_part) {
    if (!std::isdigit(static_cast<unsigned char>(ch))) {
      return false;
    }
  }
  try {
    *major = static_cast<std::uint32_t>(std::stoul(std::string(major_part)));
    *minor = static_cast<std::uint32_t>(std::stoul(std::string(minor_part)));
  } catch (const std::exception&) {
    return false;
  }
  return true;
}

grpc::Status ValidateProtocolVersion(grpc::ServerContext* context) {
  if (!context) {
    return grpc::Status(grpc::StatusCode::INTERNAL, "missing server context");
  }
  const auto& metadata = context->client_metadata();
  const auto it = metadata.find(std::string(kProtocolMetadataKey));
  if (it == metadata.end()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "protocol version metadata is required");
  }

  std::uint32_t major = 0;
  std::uint32_t minor = 0;
  const std::string_view value(it->second.data(), it->second.length());
  if (!ParseProtocolVersion(value, &major, &minor)) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "malformed protocol version metadata");
  }
  if (major != kSupportedProtocolMajor) {
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        "unsupported protocol major version");
  }

  const std::uint32_t selected_minor = std::min(minor, kSupportedProtocolMinor);
  context->AddInitialMetadata(
      std::string(kSelectedProtocolMetadataKey),
      FormatProtocolVersion(kSupportedProtocolMajor, selected_minor));
  return grpc::Status::OK;
}

std::string FormatTimestamp(std::chrono::system_clock::time_point now) {
  const std::time_t time = std::chrono::system_clock::to_time_t(now);
  std::tm utc_time{};
#if defined(_WIN32)
  gmtime_s(&utc_time, &time);
#else
  gmtime_r(&time, &utc_time);
#endif
  std::ostringstream stream;
  stream << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
  return stream.str();
}

void LogAuthEvent(std::string_view ip,
                  std::string_view action,
                  const grpc::Status& status,
                  std::string_view user_uuid) {
  std::ostringstream stream;
  stream << "{"
         << "\"timestamp\":\"" << FormatTimestamp(std::chrono::system_clock::now())
         << "\",\"ip\":\"" << veritas::gatekeeper::JsonEscape(ip)
         << "\",\"action\":\"" << veritas::gatekeeper::JsonEscape(action)
         << "\",\"status\":\"" << status.error_code() << "\"";
  if (!user_uuid.empty()) {
    stream << ",\"user_uuid\":\""
           << veritas::gatekeeper::JsonEscape(user_uuid) << "\"";
  }
  stream << "}";
  std::cout << stream.str() << std::endl;
}

}  // namespace

GatekeeperServiceImpl::GatekeeperServiceImpl(
    int rate_limit_per_minute,
    veritas::gatekeeper::SaslServerOptions options)
    : sasl_server_(std::move(options)),
      rate_limiter_(rate_limit_per_minute, std::chrono::seconds(60)) {}

grpc::Status GatekeeperServiceImpl::BeginAuth(grpc::ServerContext* context,
                                              const BeginAuthRequest* request,
                                              BeginAuthResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  const grpc::Status protocol_status = ValidateProtocolVersion(context);
  if (!protocol_status.ok()) {
    metrics_.Record(peer_ip, "", false);
    metrics_.RecordSecurityEvent("protocol_version_rejected");
    LogAuthEvent(peer_ip, "BeginAuth", protocol_status, "");
    return protocol_status;
  }
  grpc::Status status;
  if (!rate_limiter_.Allow(peer_ip)) {
    status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                          "Rate limit exceeded");
    metrics_.RecordSecurityEvent("rate_limit_exceeded");
  } else {
    status = sasl_server_.BeginAuth(*request, response);
  }
  metrics_.Record(peer_ip, "", status.ok());
  if (!status.ok()) {
    metrics_.RecordSecurityEvent("auth_failure");
  }
  LogAuthEvent(peer_ip, "BeginAuth", status, "");
  return status;
}

grpc::Status GatekeeperServiceImpl::FinishAuth(grpc::ServerContext* context,
                                               const FinishAuthRequest* request,
                                               FinishAuthResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  const grpc::Status protocol_status = ValidateProtocolVersion(context);
  if (!protocol_status.ok()) {
    metrics_.Record(peer_ip, "", false);
    metrics_.RecordSecurityEvent("protocol_version_rejected");
    LogAuthEvent(peer_ip, "FinishAuth", protocol_status, "");
    return protocol_status;
  }
  grpc::Status status;
  if (!rate_limiter_.Allow(peer_ip)) {
    status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                          "Rate limit exceeded");
    metrics_.RecordSecurityEvent("rate_limit_exceeded");
  } else {
    status = sasl_server_.FinishAuth(*request, response);
  }
  const std::string user_uuid = status.ok() ? response->user_uuid() : "";
  metrics_.Record(peer_ip, user_uuid, status.ok());
  if (!status.ok()) {
    metrics_.RecordSecurityEvent("auth_failure");
  }
  LogAuthEvent(peer_ip, "FinishAuth", status, user_uuid);
  return status;
}

grpc::Status GatekeeperServiceImpl::RevokeToken(
    grpc::ServerContext* context,
    const RevokeTokenRequest* request,
    RevokeTokenResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  const grpc::Status protocol_status = ValidateProtocolVersion(context);
  if (!protocol_status.ok()) {
    metrics_.Record(peer_ip, "", false);
    metrics_.RecordSecurityEvent("protocol_version_rejected");
    LogAuthEvent(peer_ip, "RevokeToken", protocol_status, "");
    return protocol_status;
  }
  grpc::Status status;
  if (!rate_limiter_.Allow(peer_ip)) {
    status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                          "Rate limit exceeded");
    metrics_.RecordSecurityEvent("rate_limit_exceeded");
  } else {
    status = sasl_server_.RevokeToken(*request, response);
  }
  metrics_.Record(peer_ip, "", status.ok());
  if (status.ok()) {
    metrics_.RecordSecurityEvent("token_revoked");
  }
  LogAuthEvent(peer_ip, "RevokeToken", status, "");
  return status;
}

grpc::Status GatekeeperServiceImpl::GetTokenStatus(
    grpc::ServerContext* context,
    const GetTokenStatusRequest* request,
    GetTokenStatusResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  const grpc::Status protocol_status = ValidateProtocolVersion(context);
  if (!protocol_status.ok()) {
    metrics_.Record(peer_ip, "", false);
    metrics_.RecordSecurityEvent("protocol_version_rejected");
    LogAuthEvent(peer_ip, "GetTokenStatus", protocol_status, "");
    return protocol_status;
  }
  grpc::Status status;
  if (!rate_limiter_.Allow(peer_ip)) {
    status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                          "Rate limit exceeded");
    metrics_.RecordSecurityEvent("rate_limit_exceeded");
  } else {
    status = sasl_server_.GetTokenStatus(*request, response);
  }
  metrics_.Record(peer_ip, "", status.ok());
  LogAuthEvent(peer_ip, "GetTokenStatus", status, "");
  return status;
}

}  // namespace veritas::auth::v1
