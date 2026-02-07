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

  std::string sasl_username = username;
  if (const char* realm = std::getenv("SASL_REALM")) {
    if (realm[0] != '\0' && sasl_username.find('@') == std::string::npos) {
      sasl_username.append("@").append(realm);
    }
  }

  SecureString password_buffer(password);
  SaslClient sasl_client("veritas_gatekeeper", sasl_username,
                         password_buffer.view());

  const std::string client_start = sasl_client.Start();
  const auto begin = client_.BeginAuth(sasl_username, client_start);
  const std::string client_proof =
      sasl_client.ComputeClientProof(begin.server_public);
  auto finish = client_.FinishAuth(begin.session_id, client_proof);

  sasl_client.VerifyServerProof(finish.server_proof);
  return finish.result;
}

}  // namespace veritas::auth
