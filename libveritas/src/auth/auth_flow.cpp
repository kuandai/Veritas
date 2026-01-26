#include "auth_flow.h"

#include <stdexcept>

#include "sasl_client.h"
#include "secure_buffer.h"

namespace veritas::auth {

AuthFlow::AuthFlow(const GatekeeperClientConfig& config) : client_(config) {}

AuthResult AuthFlow::Authenticate(const std::string& username,
                                  const std::string& password) {
  if (username.empty()) {
    throw std::runtime_error("Username is required");
  }
  if (password.empty()) {
    throw std::runtime_error("Password is required");
  }

  SecureString password_buffer(password);
  SaslClient sasl_client("veritas_gatekeeper", username, password_buffer.view());

  const auto begin = client_.BeginAuth(username);
  const std::string client_proof =
      sasl_client.ComputeClientProof(begin.server_public);
  auto finish = client_.FinishAuth(begin.session_id, client_proof);

  sasl_client.VerifyServerProof(finish.server_proof);
  return finish.result;
}

}  // namespace veritas::auth
