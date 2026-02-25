#include <chrono>
#include <exception>
#include <iostream>
#include <memory>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

#include "config.h"
#include "gatekeeper_service.h"
#include "tls_utils.h"
#include "token_store.h"

int main() {
  try {
    const auto config = veritas::gatekeeper::LoadConfig();
    const auto cert = veritas::gatekeeper::ReadFile(config.tls_cert_path);
    const auto key = veritas::gatekeeper::ReadFile(config.tls_key_path);
    std::string ca_bundle;
    if (!config.tls_ca_path.empty()) {
      ca_bundle = veritas::gatekeeper::ReadFile(config.tls_ca_path);
    }

    veritas::gatekeeper::ValidateTlsCredentials(cert, key, ca_bundle);

    grpc::experimental::IdentityKeyCertPair key_cert_pair{key, cert};
    auto provider =
        std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
            ca_bundle,
            std::vector<grpc::experimental::IdentityKeyCertPair>{key_cert_pair});

    grpc::experimental::TlsServerCredentialsOptions tls_opts(provider);
    tls_opts.watch_identity_key_cert_pairs();
    if (!ca_bundle.empty()) {
      tls_opts.watch_root_certs();
    }
    tls_opts.set_min_tls_version(TLS1_3);
    tls_opts.set_max_tls_version(TLS1_3);
    if (config.tls_require_client_cert) {
      tls_opts.set_cert_request_type(
          GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    } else {
      tls_opts.set_cert_request_type(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    }

    veritas::gatekeeper::SaslServerOptions sasl_options;
    sasl_options.fake_salt_secret = config.fake_salt_secret;
    sasl_options.token_ttl_days = config.token_ttl_days;
    sasl_options.token_rotation_grace_ttl =
        std::chrono::seconds(config.token_rotation_grace_seconds);
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
                             grpc::experimental::TlsServerCredentials(tls_opts));
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
