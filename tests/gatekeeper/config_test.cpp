#include "config.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {
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
  ScopedEnv bind{"BIND_ADDR", "127.0.0.1:1"};
  ScopedEnv cert{"TLS_CERT", "/tmp/test-cert.pem"};
  ScopedEnv key{"TLS_KEY", "/tmp/test-key.pem"};
};

}  // namespace

TEST(ConfigTest, LoadConfigRequiresCaBundleWhenClientCertsRequired) {
  RequiredEnv env;
  ScopedEnv require_client("TLS_REQUIRE_CLIENT_CERT", "true");
  ScopedEnv ca_bundle("TLS_CA_BUNDLE", nullptr);

  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(ConfigTest, LoadConfigAcceptsClientCertsWithBundle) {
  RequiredEnv env;
  ScopedEnv require_client("TLS_REQUIRE_CLIENT_CERT", "true");
  ScopedEnv ca_bundle("TLS_CA_BUNDLE", "/tmp/ca.pem");

  EXPECT_NO_THROW(LoadConfig());
}

TEST(ConfigTest, LoadConfigRejectsSaslDisabled) {
  RequiredEnv env;
  ScopedEnv disable_sasl("SASL_ENABLE", "false");

  EXPECT_THROW(LoadConfig(), std::runtime_error);
}

TEST(ConfigTest, ReadFileReturnsContents) {
  const std::string path = TempPath("veritas_readfile");
  {
    std::ofstream out(path, std::ios::binary);
    out << "test-data";
  }

  EXPECT_EQ(ReadFile(path), "test-data");
  std::filesystem::remove(path);
}

TEST(ConfigTest, ReadFileMissingThrows) {
  const std::string missing = TempPath("veritas_missing");
  EXPECT_THROW(ReadFile(missing), std::runtime_error);
}

}  // namespace veritas::gatekeeper
