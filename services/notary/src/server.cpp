#include "server.h"

#include <vector>

#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

#include "config.h"
#include "signer.h"
#include "tls_utils.h"

namespace veritas::notary {
namespace {

std::string BuildBoundAddress(const std::string& original_bind_addr,
                              int selected_port) {
  if (selected_port <= 0) {
    return original_bind_addr;
  }
  const auto pos = original_bind_addr.rfind(':');
  if (pos == std::string::npos) {
    return original_bind_addr;
  }
  return original_bind_addr.substr(0, pos + 1) + std::to_string(selected_port);
}

}  // namespace

NotaryRuntime StartNotaryServer(const NotaryConfig& config,
                                NotaryServiceImpl* service) {
  const auto cert = ReadFile(config.tls_cert_path);
  const auto key = ReadFile(config.tls_key_path);
  std::string ca_bundle;
  if (!config.tls_ca_path.empty()) {
    ca_bundle = ReadFile(config.tls_ca_path);
  }

  ValidateServerTlsCredentials(cert, key, ca_bundle);
  ValidateSignerKeyMaterial(
      SignerConfig{config.signer_cert_path, config.signer_key_path,
                   config.signer_chain_path});

  grpc::EnableDefaultHealthCheckService(true);

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

  grpc::ServerBuilder builder;
  int selected_port = 0;
  builder.AddListeningPort(config.bind_addr,
                           grpc::experimental::TlsServerCredentials(tls_opts),
                           &selected_port);
  builder.RegisterService(service);
  auto server = builder.BuildAndStart();
  if (!server) {
    throw std::runtime_error("failed to build notary gRPC server");
  }

  auto* health = server->GetHealthCheckService();
  if (health) {
    health->SetServingStatus("", true);
    health->SetServingStatus("veritas.notary.v1.Notary", true);
  }

  NotaryRuntime runtime;
  runtime.bound_addr = BuildBoundAddress(config.bind_addr, selected_port);
  runtime.server = std::move(server);
  return runtime;
}

}  // namespace veritas::notary
