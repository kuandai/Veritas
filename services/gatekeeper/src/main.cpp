#include <exception>
#include <iostream>
#include <memory>

#include <grpcpp/grpcpp.h>

#include "config.h"
#include "gatekeeper_service.h"
#include "token_store.h"

int main() {
  try {
    const auto config = veritas::gatekeeper::LoadConfig();
    const auto cert = veritas::gatekeeper::ReadFile(config.tls_cert_path);
    const auto key = veritas::gatekeeper::ReadFile(config.tls_key_path);

    grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert{key, cert};
    grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_key_cert_pairs.push_back(key_cert);

    veritas::gatekeeper::SaslServerOptions sasl_options;
    sasl_options.fake_salt_secret = config.fake_salt_secret;
    sasl_options.token_ttl_days = config.token_ttl_days;
    sasl_options.enable_sasl = config.enable_sasl;
    sasl_options.sasl_service = config.sasl_service;
    sasl_options.sasl_mech_list = config.sasl_mech_list;
    sasl_options.sasl_conf_path = config.sasl_conf_path;
    sasl_options.sasl_plugin_path = config.sasl_plugin_path;
    sasl_options.sasl_dbname = config.sasl_dbname;
    sasl_options.sasl_realm = config.sasl_realm;
    if (!config.token_store_uri.empty()) {
      sasl_options.token_store = std::make_shared<veritas::gatekeeper::RedisTokenStore>(
          config.token_store_uri);
    }

    veritas::auth::v1::GatekeeperServiceImpl service(
        config.rate_limit_per_minute, sasl_options);
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
