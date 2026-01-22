#include "gatekeeper_service.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>
#include <utility>

namespace veritas::auth::v1 {

namespace {

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
         << "\",\"ip\":\"" << ip << "\",\"action\":\"" << action
         << "\",\"status\":\"" << status.error_code() << "\"";
  if (!user_uuid.empty()) {
    stream << ",\"user_uuid\":\"" << user_uuid << "\"";
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
  if (!rate_limiter_.Allow(peer_ip)) {
    grpc::Status status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                        "Rate limit exceeded");
    LogAuthEvent(peer_ip, "BeginAuth", status, "");
    return status;
  }
  grpc::Status status = sasl_server_.BeginAuth(*request, response);
  LogAuthEvent(peer_ip, "BeginAuth", status, "");
  return status;
}

grpc::Status GatekeeperServiceImpl::FinishAuth(grpc::ServerContext* context,
                                               const FinishAuthRequest* request,
                                               FinishAuthResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  if (!rate_limiter_.Allow(peer_ip)) {
    grpc::Status status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                        "Rate limit exceeded");
    LogAuthEvent(peer_ip, "FinishAuth", status, "");
    return status;
  }
  grpc::Status status = sasl_server_.FinishAuth(*request, response);
  LogAuthEvent(peer_ip, "FinishAuth", status, response->user_uuid());
  return status;
}

}  // namespace veritas::auth::v1
