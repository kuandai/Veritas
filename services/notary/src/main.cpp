#include <exception>
#include <iostream>

#include <grpcpp/support/status.h>

#include "authorizer.h"
#include "config.h"
#include "log_utils.h"
#include "notary_service.h"
#include "server.h"

int main() {
  try {
    const auto config = veritas::notary::LoadConfig();

    std::string gatekeeper_root_ca;
    if (!config.gatekeeper_ca_path.empty()) {
      gatekeeper_root_ca = veritas::notary::ReadFile(config.gatekeeper_ca_path);
    }

    veritas::notary::GatekeeperTokenStatusClientConfig status_client_config;
    status_client_config.target = config.gatekeeper_target;
    status_client_config.root_ca_pem = gatekeeper_root_ca;
    status_client_config.allow_insecure = config.gatekeeper_allow_insecure;
    auto status_client = std::make_shared<veritas::notary::GatekeeperTokenStatusClient>(
        status_client_config);
    auto authorizer = std::make_shared<veritas::notary::RefreshTokenAuthorizer>(
        status_client);

    veritas::notary::NotaryServiceImpl service(authorizer);
    auto runtime = veritas::notary::StartNotaryServer(config, &service);
    veritas::notary::LogNotaryEvent("Startup", grpc::Status::OK,
                                    runtime.bound_addr);
    runtime.server->Wait();
  } catch (const std::exception& ex) {
    std::cerr << "Notary startup failed: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
