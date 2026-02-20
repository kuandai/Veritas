#include "config.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace veritas::notary {
namespace {

std::string GetEnvOrEmpty(const char* name) {
  const char* value = std::getenv(name);
  return value ? std::string(value) : std::string();
}

bool GetEnvOrDefaultBool(const char* name, bool fallback) {
  const char* value = std::getenv(name);
  if (!value || value[0] == '\0') {
    return fallback;
  }
  std::string normalized(value);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  if (normalized == "1" || normalized == "true" || normalized == "yes") {
    return true;
  }
  if (normalized == "0" || normalized == "false" || normalized == "no") {
    return false;
  }
  return fallback;
}

}  // namespace

NotaryConfig LoadConfig() {
  NotaryConfig config;
  config.bind_addr = GetEnvOrEmpty("NOTARY_BIND_ADDR");
  config.tls_cert_path = GetEnvOrEmpty("NOTARY_TLS_CERT");
  config.tls_key_path = GetEnvOrEmpty("NOTARY_TLS_KEY");
  config.tls_ca_path = GetEnvOrEmpty("NOTARY_TLS_CA_BUNDLE");
  config.tls_require_client_cert =
      GetEnvOrDefaultBool("NOTARY_TLS_REQUIRE_CLIENT_CERT", false);
  config.signer_cert_path = GetEnvOrEmpty("NOTARY_SIGNER_CERT");
  config.signer_key_path = GetEnvOrEmpty("NOTARY_SIGNER_KEY");
  config.signer_chain_path = GetEnvOrEmpty("NOTARY_SIGNER_CHAIN");

  if (config.bind_addr.empty()) {
    throw std::runtime_error("NOTARY_BIND_ADDR is required");
  }
  if (config.tls_cert_path.empty()) {
    throw std::runtime_error("NOTARY_TLS_CERT is required");
  }
  if (config.tls_key_path.empty()) {
    throw std::runtime_error("NOTARY_TLS_KEY is required");
  }
  if (config.signer_cert_path.empty()) {
    throw std::runtime_error("NOTARY_SIGNER_CERT is required");
  }
  if (config.signer_key_path.empty()) {
    throw std::runtime_error("NOTARY_SIGNER_KEY is required");
  }
  if (config.tls_require_client_cert && config.tls_ca_path.empty()) {
    throw std::runtime_error(
        "NOTARY_TLS_CA_BUNDLE is required when mTLS is enabled");
  }

  return config;
}

std::string ReadFile(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path);
  }
  std::ostringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

}  // namespace veritas::notary
