#include "config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace veritas::gatekeeper {

namespace {

std::string GetEnvOrEmpty(const char* name) {
  const char* value = std::getenv(name);
  return value ? std::string(value) : std::string();
}

int GetEnvOrDefaultInt(const char* name, int fallback) {
  const char* value = std::getenv(name);
  if (!value || value[0] == '\0') {
    return fallback;
  }
  return std::stoi(value);
}

}  // namespace

GatekeeperConfig LoadConfig() {
  GatekeeperConfig config;
  config.bind_addr = GetEnvOrEmpty("BIND_ADDR");
  config.tls_cert_path = GetEnvOrEmpty("TLS_CERT");
  config.tls_key_path = GetEnvOrEmpty("TLS_KEY");
  config.token_ttl_days = GetEnvOrDefaultInt("TOKEN_TTL_DAYS", 30);
  config.rate_limit_per_minute = GetEnvOrDefaultInt("RATE_LIMIT", 5);
  config.token_store_uri = GetEnvOrEmpty("TOKEN_STORE_URI");
  config.fake_salt_secret = GetEnvOrEmpty("FAKE_SALT_SECRET");

  if (config.bind_addr.empty()) {
    throw std::runtime_error("BIND_ADDR is required");
  }
  if (config.tls_cert_path.empty()) {
    throw std::runtime_error("TLS_CERT is required");
  }
  if (config.tls_key_path.empty()) {
    throw std::runtime_error("TLS_KEY is required");
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

}  // namespace veritas::gatekeeper
