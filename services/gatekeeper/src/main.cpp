#include <exception>
#include <iostream>
#include <memory>

#include <grpcpp/grpcpp.h>

#include "config.h"
#include "gatekeeper_service.h"

int main() {
  try {
    const auto config = veritas::gatekeeper::LoadConfig();
    const auto cert = veritas::gatekeeper::ReadFile(config.tls_cert_path);
    const auto key = veritas::gatekeeper::ReadFile(config.tls_key_path);

    grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert{key, cert};
    grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_key_cert_pairs.push_back(key_cert);

    veritas::auth::v1::GatekeeperServiceImpl service;
    grpc::ServerBuilder builder;
    builder.AddListeningPort(config.bind_addr,
                             grpc::SslServerCredentials(ssl_opts));
    builder.RegisterService(&service);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    if (!server) {
      std::cerr << "Failed to start Gatekeeper server\n";
      return 1;
    }

    std::cout << "Gatekeeper listening on " << config.bind_addr << "\n";
    server->Wait();
  } catch (const std::exception& ex) {
    std::cerr << "Gatekeeper startup failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
