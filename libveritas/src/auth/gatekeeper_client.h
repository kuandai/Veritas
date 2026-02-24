#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <stdexcept>

#include <grpcpp/grpcpp.h>

#include "gatekeeper.grpc.pb.h"
#include "veritas/identity_manager.h"

namespace veritas::auth {

struct BeginAuthResult {
  std::string session_id;
  std::string server_public;
};

struct FinishAuthResult {
  AuthResult result;
  std::string server_proof;
};

enum class TokenStatusState {
  Unknown,
  Active,
  Revoked,
};

struct TokenStatusResult {
  TokenStatusState state = TokenStatusState::Unknown;
  std::string reason;
  std::chrono::system_clock::time_point revoked_at{};
};

class GatekeeperClient {
 public:
  explicit GatekeeperClient(const GatekeeperClientConfig& config);

  BeginAuthResult BeginAuth(const std::string& username,
                            std::string_view client_start);
  FinishAuthResult FinishAuth(const std::string& session_id,
                              const std::string& client_proof);
  void RevokeToken(const std::string& refresh_token,
                   const std::string& reason);
  TokenStatusResult GetTokenStatus(const std::string& refresh_token);

 private:
  GatekeeperClientConfig config_;
  std::shared_ptr<grpc::Channel> channel_;
  std::unique_ptr<veritas::auth::v1::Gatekeeper::Stub> stub_;
};

class GatekeeperError : public std::runtime_error {
 public:
  GatekeeperError(grpc::StatusCode code, std::string message)
      : std::runtime_error(std::move(message)), code_(code) {}

  grpc::StatusCode code() const noexcept { return code_; }

 private:
  grpc::StatusCode code_;
};

}  // namespace veritas::auth
