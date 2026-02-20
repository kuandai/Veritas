#include <exception>
#include <iostream>

#include <grpcpp/support/status.h>

#include "config.h"
#include "log_utils.h"
#include "notary_service.h"
#include "server.h"

int main() {
  try {
    const auto config = veritas::notary::LoadConfig();
    veritas::notary::NotaryServiceImpl service;
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
