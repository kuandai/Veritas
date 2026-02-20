#pragma once

#include <string>

namespace veritas::notary {

struct NotaryConfig {
  std::string bind_addr;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string tls_ca_path;
  bool tls_require_client_cert = false;

  std::string signer_cert_path;
  std::string signer_key_path;
  std::string signer_chain_path;
};

NotaryConfig LoadConfig();
std::string ReadFile(const std::string& path);

}  // namespace veritas::notary
