#include "config.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace veritas::notary {
namespace {

std::string GetEnvOrEmpty(const char* name) {
  const char* value = std::getenv(name);
  return value ? std::string(value) : std::string();
}

std::string ToLowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
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

size_t GetEnvOrDefaultSize(const char* name, size_t fallback) {
  const char* value = std::getenv(name);
  if (!value || value[0] == '\0') {
    return fallback;
  }

  errno = 0;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(value, &end, 10);
  if (errno != 0 || end == value || (end && *end != '\0') || parsed == 0 ||
      parsed > std::numeric_limits<size_t>::max()) {
    throw std::runtime_error(std::string(name) +
                             " must be a positive integer");
  }
  return static_cast<size_t>(parsed);
}

NotaryStoreBackend ParseStoreBackend(const std::string& value) {
  if (value.empty() || value == "memory" || value == "in-memory") {
    return NotaryStoreBackend::InMemory;
  }
  if (value == "redis") {
    return NotaryStoreBackend::Redis;
  }
  throw std::runtime_error(
      "NOTARY_STORE_BACKEND must be one of: memory, in-memory, redis");
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
  config.signer_not_before_skew_seconds = GetEnvOrDefaultSize(
      "NOTARY_SIGNER_NOT_BEFORE_SKEW_SECONDS",
      config.signer_not_before_skew_seconds);
  const std::string signer_hash =
      GetEnvOrEmpty("NOTARY_SIGNER_HASH_ALGORITHM");
  if (!signer_hash.empty()) {
    config.signer_hash_algorithm = ToLowerAscii(signer_hash);
  } else {
    config.signer_hash_algorithm = "sha256";
  }
  config.gatekeeper_target = GetEnvOrEmpty("NOTARY_GATEKEEPER_TARGET");
  config.gatekeeper_ca_path = GetEnvOrEmpty("NOTARY_GATEKEEPER_CA_BUNDLE");
  config.gatekeeper_allow_insecure =
      GetEnvOrDefaultBool("NOTARY_GATEKEEPER_ALLOW_INSECURE", false);
  config.store_backend =
      ParseStoreBackend(GetEnvOrEmpty("NOTARY_STORE_BACKEND"));
  config.store_uri = GetEnvOrEmpty("NOTARY_STORE_URI");
  config.rate_limit_identity_max_requests = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_IDENTITY_MAX_REQUESTS",
      config.rate_limit_identity_max_requests);
  config.rate_limit_identity_max_keys = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_IDENTITY_MAX_KEYS",
      config.rate_limit_identity_max_keys);
  config.rate_limit_identity_window_seconds = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_IDENTITY_WINDOW_SECONDS",
      config.rate_limit_identity_window_seconds);
  config.rate_limit_peer_max_requests = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_PEER_MAX_REQUESTS",
      config.rate_limit_peer_max_requests);
  config.rate_limit_peer_max_keys = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_PEER_MAX_KEYS",
      config.rate_limit_peer_max_keys);
  config.rate_limit_peer_window_seconds = GetEnvOrDefaultSize(
      "NOTARY_RATE_LIMIT_PEER_WINDOW_SECONDS",
      config.rate_limit_peer_window_seconds);

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
  if (config.signer_not_before_skew_seconds > 3600) {
    throw std::runtime_error(
        "NOTARY_SIGNER_NOT_BEFORE_SKEW_SECONDS must be between 1 and 3600");
  }
  if (config.signer_hash_algorithm != "sha256") {
    throw std::runtime_error(
        "NOTARY_SIGNER_HASH_ALGORITHM must be sha256");
  }
  if (config.gatekeeper_target.empty()) {
    throw std::runtime_error("NOTARY_GATEKEEPER_TARGET is required");
  }
  if (!config.gatekeeper_allow_insecure && config.gatekeeper_ca_path.empty()) {
    throw std::runtime_error(
        "NOTARY_GATEKEEPER_CA_BUNDLE is required unless insecure gatekeeper mode is enabled");
  }
  if (config.tls_require_client_cert && config.tls_ca_path.empty()) {
    throw std::runtime_error(
        "NOTARY_TLS_CA_BUNDLE is required when mTLS is enabled");
  }
  if (config.store_backend == NotaryStoreBackend::Redis &&
      config.store_uri.empty()) {
    throw std::runtime_error(
        "NOTARY_STORE_URI is required when NOTARY_STORE_BACKEND=redis");
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
