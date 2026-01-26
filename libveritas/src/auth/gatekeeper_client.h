#pragma once

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

class GatekeeperClient {
 public:
  explicit GatekeeperClient(const GatekeeperClientConfig& config);

  BeginAuthResult BeginAuth(const std::string& username);
  FinishAuthResult FinishAuth(const std::string& session_id,
                              const std::string& client_proof);

 private:
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
