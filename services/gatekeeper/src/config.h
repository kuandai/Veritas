#pragma once

#include <string>

namespace veritas::gatekeeper {

struct GatekeeperConfig {
  std::string bind_addr;
  std::string tls_cert_path;
  std::string tls_key_path;
  int token_ttl_days = 30;
  int rate_limit_per_minute = 5;
  std::string token_store_uri;
  std::string fake_salt_secret;
};

GatekeeperConfig LoadConfig();
std::string ReadFile(const std::string& path);

}  // namespace veritas::gatekeeper
