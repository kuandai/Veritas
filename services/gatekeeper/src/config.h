#pragma once

#include <string>

namespace veritas::gatekeeper {

struct GatekeeperConfig {
  std::string bind_addr;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string tls_ca_path;
  bool tls_require_client_cert = false;
  int token_ttl_days = 30;
  int token_rotation_grace_seconds = 60;
  int rate_limit_per_minute = 5;
  std::string token_store_uri;
  std::string fake_salt_secret;
  bool enable_sasl = true;
  std::string sasl_service = "veritas_gatekeeper";
  std::string sasl_mech_list = "SRP";
  std::string sasl_conf_path;
  std::string sasl_plugin_path;
  std::string sasl_dbname;
  std::string sasl_realm;
};

GatekeeperConfig LoadConfig();
std::string ReadFile(const std::string& path);

}  // namespace veritas::gatekeeper
