#include "config.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace veritas::notary {
namespace {

class ScopedEnv {
 public:
  ScopedEnv(const char* key, const std::string& value) : key_(key) {
    const char* existing = std::getenv(key);
    if (existing) {
      had_value_ = true;
      old_value_ = existing;
    }
    setenv(key, value.c_str(), 1);
  }

  ScopedEnv(const char* key, std::nullptr_t) : key_(key) {
    const char* existing = std::getenv(key);
    if (existing) {
      had_value_ = true;
      old_value_ = existing;
    }
    unsetenv(key);
  }

  ~ScopedEnv() {
    if (had_value_) {
      setenv(key_.c_str(), old_value_.c_str(), 1);
    } else {
      unsetenv(key_.c_str());
    }
  }

 private:
  std::string key_;
  bool had_value_ = false;
  std::string old_value_;
};

std::string TempPath(const std::string& name) {
  const auto base = std::filesystem::temp_directory_path();
  const auto stamp = std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count());
  return (base / (name + "_" + stamp)).string();
}

struct RequiredEnv {
  ScopedEnv bind{"NOTARY_BIND_ADDR", "127.0.0.1:1"};
  ScopedEnv cert{"NOTARY_TLS_CERT", "/tmp/notary-cert.pem"};
  ScopedEnv key{"NOTARY_TLS_KEY", "/tmp/notary-key.pem"};
  ScopedEnv signer_cert{"NOTARY_SIGNER_CERT", "/tmp/notary-signer-cert.pem"};
  ScopedEnv signer_key{"NOTARY_SIGNER_KEY", "/tmp/notary-signer-key.pem"};
  ScopedEnv gatekeeper_target{"NOTARY_GATEKEEPER_TARGET", "127.0.0.1:50051"};
  ScopedEnv gatekeeper_insecure{"NOTARY_GATEKEEPER_ALLOW_INSECURE", "true"};
};

}  // namespace

TEST(NotaryConfigTest, RequiresCaBundleWhenClientCertsEnabled) {
  RequiredEnv env;
  ScopedEnv require_client("NOTARY_TLS_REQUIRE_CLIENT_CERT", "true");
  ScopedEnv ca_bundle("NOTARY_TLS_CA_BUNDLE", nullptr);
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, RequiresSignerKeyMaterialPaths) {
  RequiredEnv env;
  ScopedEnv signer_cert("NOTARY_SIGNER_CERT", nullptr);
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, LoadsValidConfiguration) {
  RequiredEnv env;
  ScopedEnv require_client("NOTARY_TLS_REQUIRE_CLIENT_CERT", "false");
  const auto config = LoadConfig();
  EXPECT_EQ(config.store_backend, NotaryStoreBackend::InMemory);
}

TEST(NotaryConfigTest, LoadsRateLimitOverrides) {
  RequiredEnv env;
  ScopedEnv identity_max("NOTARY_RATE_LIMIT_IDENTITY_MAX_REQUESTS", "9");
  ScopedEnv identity_keys("NOTARY_RATE_LIMIT_IDENTITY_MAX_KEYS", "321");
  ScopedEnv identity_window("NOTARY_RATE_LIMIT_IDENTITY_WINDOW_SECONDS", "1800");
  ScopedEnv peer_max("NOTARY_RATE_LIMIT_PEER_MAX_REQUESTS", "200");
  ScopedEnv peer_keys("NOTARY_RATE_LIMIT_PEER_MAX_KEYS", "444");
  ScopedEnv peer_window("NOTARY_RATE_LIMIT_PEER_WINDOW_SECONDS", "120");

  const auto config = LoadConfig();
  EXPECT_EQ(config.rate_limit_identity_max_requests, 9U);
  EXPECT_EQ(config.rate_limit_identity_max_keys, 321U);
  EXPECT_EQ(config.rate_limit_identity_window_seconds, 1800U);
  EXPECT_EQ(config.rate_limit_peer_max_requests, 200U);
  EXPECT_EQ(config.rate_limit_peer_max_keys, 444U);
  EXPECT_EQ(config.rate_limit_peer_window_seconds, 120U);
}

TEST(NotaryConfigTest, LoadsSignerPolicyOverrides) {
  RequiredEnv env;
  ScopedEnv signer_skew("NOTARY_SIGNER_NOT_BEFORE_SKEW_SECONDS", "1200");
  ScopedEnv signer_hash("NOTARY_SIGNER_HASH_ALGORITHM", "sha256");

  const auto config = LoadConfig();
  EXPECT_EQ(config.signer_not_before_skew_seconds, 1200U);
  EXPECT_EQ(config.signer_hash_algorithm, "sha256");
}

TEST(NotaryConfigTest, LoadsRevokedTokenAbusePolicyOverrides) {
  RequiredEnv env;
  ScopedEnv threshold("NOTARY_REVOKED_TOKEN_ABUSE_THRESHOLD", "7");
  ScopedEnv window("NOTARY_REVOKED_TOKEN_ABUSE_WINDOW_SECONDS", "900");
  ScopedEnv enforcement("NOTARY_REVOKED_TOKEN_ENFORCEMENT_ENABLED", "true");
  ScopedEnv duration("NOTARY_REVOKED_TOKEN_ENFORCEMENT_DURATION_SECONDS", "120");

  const auto config = LoadConfig();
  EXPECT_EQ(config.revoked_token_abuse_threshold, 7U);
  EXPECT_EQ(config.revoked_token_abuse_window_seconds, 900U);
  EXPECT_TRUE(config.revoked_token_enforcement_enabled);
  EXPECT_EQ(config.revoked_token_enforcement_duration_seconds, 120U);
}

TEST(NotaryConfigTest, InvalidRateLimitConfigFailsClosed) {
  RequiredEnv env;
  ScopedEnv invalid_identity_max("NOTARY_RATE_LIMIT_IDENTITY_MAX_REQUESTS", "0");
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, InvalidSignerSkewConfigFailsClosed) {
  RequiredEnv env;
  ScopedEnv invalid_skew("NOTARY_SIGNER_NOT_BEFORE_SKEW_SECONDS", "3601");
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, InvalidSignerHashConfigFailsClosed) {
  RequiredEnv env;
  ScopedEnv invalid_hash("NOTARY_SIGNER_HASH_ALGORITHM", "sha512");
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, InvalidRevokedTokenAbusePolicyFailsClosed) {
  RequiredEnv env;
  ScopedEnv invalid_threshold("NOTARY_REVOKED_TOKEN_ABUSE_THRESHOLD", "100001");
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, SecureGatekeeperModeRequiresCaBundle) {
  RequiredEnv env;
  ScopedEnv secure_gatekeeper("NOTARY_GATEKEEPER_ALLOW_INSECURE", "false");
  ScopedEnv ca_bundle("NOTARY_GATEKEEPER_CA_BUNDLE", nullptr);
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, ReadFileReturnsContents) {
  const auto path = TempPath("veritas_notary_readfile");
  {
    std::ofstream out(path, std::ios::binary);
    out << "notary-data";
  }

  EXPECT_EQ(ReadFile(path), "notary-data");
  std::filesystem::remove(path);
}

TEST(NotaryConfigTest, ReadFileMissingThrows) {
  const auto missing = TempPath("veritas_notary_missing");
  EXPECT_THROW(ReadFile(missing), std::runtime_error);
}

TEST(NotaryConfigTest, RedisStoreBackendRequiresUri) {
  RequiredEnv env;
  ScopedEnv store_backend("NOTARY_STORE_BACKEND", "redis");
  ScopedEnv store_uri("NOTARY_STORE_URI", nullptr);
  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(NotaryConfigTest, LoadsRedisStoreBackendWhenUriProvided) {
  RequiredEnv env;
  ScopedEnv store_backend("NOTARY_STORE_BACKEND", "redis");
  ScopedEnv store_uri("NOTARY_STORE_URI", "redis://127.0.0.1:6379");
  const auto config = LoadConfig();
  EXPECT_EQ(config.store_backend, NotaryStoreBackend::Redis);
  EXPECT_EQ(config.store_uri, "redis://127.0.0.1:6379");
}

}  // namespace veritas::notary
