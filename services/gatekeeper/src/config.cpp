#include "config.h"

#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <cctype>
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

bool GetEnvOrDefaultBool(const char* name, bool fallback) {
  const char* value = std::getenv(name);
  if (!value || value[0] == '\0') {
    return fallback;
  }
  std::string normalized(value);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  if (normalized == "1" || normalized == "true" || normalized == "yes") {
    return true;
  }
  if (normalized == "0" || normalized == "false" || normalized == "no") {
    return false;
  }
  return fallback;
}

}  // namespace

GatekeeperConfig LoadConfig() {
  GatekeeperConfig config;
  config.bind_addr = GetEnvOrEmpty("BIND_ADDR");
  config.tls_cert_path = GetEnvOrEmpty("TLS_CERT");
  config.tls_key_path = GetEnvOrEmpty("TLS_KEY");
  config.tls_ca_path = GetEnvOrEmpty("TLS_CA_BUNDLE");
  config.tls_require_client_cert =
      GetEnvOrDefaultBool("TLS_REQUIRE_CLIENT_CERT", false);
  config.token_ttl_days = GetEnvOrDefaultInt("TOKEN_TTL_DAYS", 30);
  config.token_rotation_grace_seconds =
      GetEnvOrDefaultInt("TOKEN_ROTATION_GRACE_SECONDS", 60);
  config.rate_limit_per_minute = GetEnvOrDefaultInt("RATE_LIMIT", 5);
  config.token_store_uri = GetEnvOrEmpty("TOKEN_STORE_URI");
  config.fake_salt_secret = GetEnvOrEmpty("FAKE_SALT_SECRET");
  config.enable_sasl = GetEnvOrDefaultBool("SASL_ENABLE", true);

  const auto sasl_service = GetEnvOrEmpty("SASL_SERVICE");
  if (!sasl_service.empty()) {
    config.sasl_service = sasl_service;
  }
  const auto sasl_mech_list = GetEnvOrEmpty("SASL_MECH_LIST");
  if (!sasl_mech_list.empty()) {
    config.sasl_mech_list = sasl_mech_list;
  }
  config.sasl_conf_path = GetEnvOrEmpty("SASL_CONF_PATH");
  config.sasl_plugin_path = GetEnvOrEmpty("SASL_PLUGIN_PATH");
  config.sasl_dbname = GetEnvOrEmpty("SASL_DBNAME");
  config.sasl_realm = GetEnvOrEmpty("SASL_REALM");

  if (!config.enable_sasl) {
    throw std::runtime_error(
        "SASL_ENABLE=false is not permitted; authentication must remain enabled");
  }

  if (config.bind_addr.empty()) {
    throw std::runtime_error("BIND_ADDR is required");
  }
  if (config.tls_cert_path.empty()) {
    throw std::runtime_error("TLS_CERT is required");
  }
  if (config.tls_key_path.empty()) {
    throw std::runtime_error("TLS_KEY is required");
  }
  if (config.tls_require_client_cert && config.tls_ca_path.empty()) {
    throw std::runtime_error(
        "TLS_CA_BUNDLE is required when TLS_REQUIRE_CLIENT_CERT is enabled");
  }
  if (config.token_rotation_grace_seconds <= 0) {
    throw std::runtime_error(
        "TOKEN_ROTATION_GRACE_SECONDS must be greater than zero");
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
