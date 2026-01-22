#include "gatekeeper_service.h"

#include <string_view>

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

}  // namespace

GatekeeperServiceImpl::GatekeeperServiceImpl(int rate_limit_per_minute)
    : rate_limiter_(rate_limit_per_minute, std::chrono::seconds(60)) {}

grpc::Status GatekeeperServiceImpl::BeginAuth(grpc::ServerContext* context,
                                              const BeginAuthRequest* request,
                                              BeginAuthResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  if (!rate_limiter_.Allow(peer_ip)) {
    return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                        "Rate limit exceeded");
  }
  return sasl_server_.BeginAuth(*request, response);
}

grpc::Status GatekeeperServiceImpl::FinishAuth(grpc::ServerContext* context,
                                               const FinishAuthRequest* request,
                                               FinishAuthResponse* response) {
  const std::string peer_ip = ExtractPeerIp(context);
  if (!rate_limiter_.Allow(peer_ip)) {
    return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                        "Rate limit exceeded");
  }
  return sasl_server_.FinishAuth(*request, response);
}

}  // namespace veritas::auth::v1
