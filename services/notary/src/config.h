#pragma once

#include <cstddef>
#include <string>

namespace veritas::notary {

enum class NotaryStoreBackend {
  InMemory,
  Redis,
};

struct NotaryConfig {
  std::string bind_addr;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string tls_ca_path;
  bool tls_require_client_cert = false;

  std::string signer_cert_path;
  std::string signer_key_path;
  std::string signer_chain_path;
  size_t signer_not_before_skew_seconds = 900;
  std::string signer_hash_algorithm = "sha256";

  std::string gatekeeper_target;
  std::string gatekeeper_ca_path;
  bool gatekeeper_allow_insecure = false;

  NotaryStoreBackend store_backend = NotaryStoreBackend::InMemory;
  std::string store_uri;

  size_t rate_limit_identity_max_requests = 5;
  size_t rate_limit_identity_max_keys = 10000;
  size_t rate_limit_identity_window_seconds = 3600;
  size_t rate_limit_peer_max_requests = 120;
  size_t rate_limit_peer_max_keys = 10000;
  size_t rate_limit_peer_window_seconds = 60;
};

NotaryConfig LoadConfig();
std::string ReadFile(const std::string& path);

}  // namespace veritas::notary
