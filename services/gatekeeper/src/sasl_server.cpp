#include "sasl_server.h"

#include <array>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <mutex>

#include <sasl/sasl.h>

#include "token_utils.h"

namespace veritas::gatekeeper {

namespace {

std::once_flag g_sasl_init_once;
grpc::Status g_sasl_init_status = grpc::Status::OK;

std::string HexEncode(const std::string& data) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (unsigned char byte : data) {
    stream << std::setw(2) << static_cast<int>(byte);
  }
  return stream.str();
}

std::string GenerateRandomBytes(std::size_t length) {
  return GenerateRefreshToken(length);
}

std::string GenerateSessionId() {
  return HexEncode(GenerateRandomBytes(16));
}

}  // namespace

SaslServer::SaslServer(SaslServerOptions options)
    : options_(std::move(options)),
      session_cache_(options_.session_ttl),
      fake_salt_(options_.fake_salt_secret) {
  EnsureInitialized();
}

void SaslServer::EnsureInitialized() {
  std::call_once(g_sasl_init_once, []() {
    const int result = sasl_server_init(nullptr, "veritas_gatekeeper");
    if (result != SASL_OK) {
      g_sasl_init_status = grpc::Status(grpc::StatusCode::INTERNAL,
                                        "SASL initialization failed");
      return;
    }
  });
}

grpc::Status SaslServer::BeginAuth(
    const veritas::auth::v1::BeginAuthRequest& request,
    veritas::auth::v1::BeginAuthResponse* response) {
  EnsureInitialized();
  if (!g_sasl_init_status.ok()) {
    return g_sasl_init_status;
  }
  if (request.login_username().empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "login_username is required");
  }

  try {
    session_cache_.CleanupExpired();
    const auto now = std::chrono::system_clock::now();
    const std::string session_id = GenerateSessionId();
    SrpSession session{session_id, request.login_username(),
                       now + options_.session_ttl};
    session_cache_.Insert(session);

    response->set_salt(fake_salt_.Generate(request.login_username()));
    response->set_server_public(GenerateRandomBytes(32));
    response->set_session_id(session_id);
    auto* params = response->mutable_params();
    params->set_group("rfc5054-4096");
    params->set_hash("sha256");
  } catch (const std::exception& ex) {
    return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }

  return grpc::Status::OK;
}

grpc::Status SaslServer::FinishAuth(
    const veritas::auth::v1::FinishAuthRequest& request,
    veritas::auth::v1::FinishAuthResponse* response) {
  EnsureInitialized();
  if (!g_sasl_init_status.ok()) {
    return g_sasl_init_status;
  }
  if (request.session_id().empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "session_id is required");
  }
  if (request.client_proof().empty()) {
    return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                        "client_proof is required");
  }

  session_cache_.CleanupExpired();
  const auto session = session_cache_.Get(request.session_id());
  if (!session) {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "session not found");
  }

  try {
    const auto now = std::chrono::system_clock::now();
    const auto expires_at =
        now + std::chrono::hours(24 * options_.token_ttl_days);
    const std::string refresh_token = GenerateRefreshToken();
    const std::string token_hash = HashTokenSha256(refresh_token);
    const std::string user_uuid = "mock-" + session->session_id;

    TokenRecord record{token_hash, user_uuid, expires_at, false};
    token_store_.PutToken(record);

    response->set_server_proof(GenerateRandomBytes(32));
    response->set_user_uuid(user_uuid);
    response->set_refresh_token(refresh_token);

    auto* ts = response->mutable_expires_at();
    const auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            expires_at.time_since_epoch())
            .count();
    ts->set_seconds(static_cast<int64_t>(seconds));
    ts->set_nanos(0);
    session_cache_.Erase(request.session_id());
  } catch (const std::exception& ex) {
    return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }

  return grpc::Status::OK;
}

}  // namespace veritas::gatekeeper
