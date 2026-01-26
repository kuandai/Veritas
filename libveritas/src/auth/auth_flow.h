#pragma once

#include <string>

#include "gatekeeper_client.h"
#include "veritas/identity_manager.h"

namespace veritas::auth {

class AuthFlow {
 public:
  explicit AuthFlow(const GatekeeperClientConfig& config);

  AuthResult Authenticate(const std::string& username,
                          const std::string& password);

 private:
  GatekeeperClient client_;
};

}  // namespace veritas::auth
