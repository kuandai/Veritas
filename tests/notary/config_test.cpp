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
  EXPECT_NO_THROW(LoadConfig());
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

}  // namespace veritas::notary
