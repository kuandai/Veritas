#include "server.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "authorizer.h"
#include "notary_service.h"

namespace veritas::notary {
namespace {

struct BioDeleter {
  void operator()(BIO* bio) const { BIO_free(bio); }
};

struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

struct PkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

struct KeyCertPair {
  std::string key_pem;
  std::string cert_pem;
};

std::string BioToString(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (!mem || !mem->data || mem->length == 0) {
    return {};
  }
  return std::string(mem->data, mem->length);
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> GenerateKey() {
  std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx) {
    throw std::runtime_error("Failed to create keygen context");
  }
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to init keygen");
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) {
    throw std::runtime_error("Failed to set key size");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
    throw std::runtime_error("Failed to generate key");
  }
  return std::unique_ptr<EVP_PKEY, PkeyDeleter>(pkey);
}

KeyCertPair GenerateSelfSigned(const std::string& common_name) {
  auto key = GenerateKey();
  std::unique_ptr<X509, X509Deleter> cert(X509_new());
  if (!cert) {
    throw std::runtime_error("Failed to allocate X509");
  }
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), -60);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 60 * 60);
  X509_set_pubkey(cert.get(), key.get());

  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(
                                 common_name.c_str()),
                             -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
    throw std::runtime_error("Failed to sign certificate");
  }

  std::unique_ptr<BIO, BioDeleter> key_bio(BIO_new(BIO_s_mem()));
  std::unique_ptr<BIO, BioDeleter> cert_bio(BIO_new(BIO_s_mem()));
  if (!key_bio || !cert_bio) {
    throw std::runtime_error("Failed to allocate BIO");
  }
  if (PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0,
                               nullptr, nullptr) != 1) {
    throw std::runtime_error("Failed to write private key");
  }
  if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
    throw std::runtime_error("Failed to write certificate");
  }
  return KeyCertPair{BioToString(key_bio.get()), BioToString(cert_bio.get())};
}

class TempDir {
 public:
  TempDir() {
    path_ = std::filesystem::temp_directory_path() /
            ("veritas_notary_server_test_" +
             std::to_string(std::chrono::steady_clock::now()
                                .time_since_epoch()
                                .count()));
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

void WriteFile(const std::filesystem::path& path, const std::string& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    throw std::runtime_error("failed to open test file for writing");
  }
  out << data;
}

class AllowAuthorizer final : public RequestAuthorizer {
 public:
  grpc::Status AuthorizeRefreshToken(
      std::string_view /*refresh_token*/) const override {
    return grpc::Status::OK;
  }
};

TEST(NotaryServerIntegrationTest, StartsWithTlsAndEnablesHealthService) {
  TempDir temp;
  const auto server_pair = GenerateSelfSigned("veritas-notary-server");
  const auto signer_pair = GenerateSelfSigned("veritas-notary-signer");

  const auto tls_cert = temp.path() / "server.crt";
  const auto tls_key = temp.path() / "server.key";
  const auto signer_cert = temp.path() / "signer.crt";
  const auto signer_key = temp.path() / "signer.key";
  WriteFile(tls_cert, server_pair.cert_pem);
  WriteFile(tls_key, server_pair.key_pem);
  WriteFile(signer_cert, signer_pair.cert_pem);
  WriteFile(signer_key, signer_pair.key_pem);

  NotaryConfig config;
  config.bind_addr = "127.0.0.1:0";
  config.tls_cert_path = tls_cert.string();
  config.tls_key_path = tls_key.string();
  config.signer_cert_path = signer_cert.string();
  config.signer_key_path = signer_key.string();

  auto authorizer = std::make_shared<AllowAuthorizer>();
  NotaryServiceImpl service(authorizer);
  auto runtime = StartNotaryServer(config, &service);
  ASSERT_TRUE(runtime.server != nullptr);
  ASSERT_EQ(runtime.bound_addr.find(":0"), std::string::npos)
      << "bound address should be updated with selected port";
  ASSERT_NE(runtime.server->GetHealthCheckService(), nullptr);

  runtime.server->Shutdown();
}

TEST(NotaryServerIntegrationTest, StartupFailsClosedOnInvalidSignerMaterial) {
  TempDir temp;
  const auto server_pair = GenerateSelfSigned("veritas-notary-server");

  const auto tls_cert = temp.path() / "server.crt";
  const auto tls_key = temp.path() / "server.key";
  const auto signer_cert = temp.path() / "signer.crt";
  const auto signer_key = temp.path() / "signer.key";
  WriteFile(tls_cert, server_pair.cert_pem);
  WriteFile(tls_key, server_pair.key_pem);
  WriteFile(signer_cert, "invalid");
  WriteFile(signer_key, "invalid");

  NotaryConfig config;
  config.bind_addr = "127.0.0.1:0";
  config.tls_cert_path = tls_cert.string();
  config.tls_key_path = tls_key.string();
  config.signer_cert_path = signer_cert.string();
  config.signer_key_path = signer_key.string();

  auto authorizer = std::make_shared<AllowAuthorizer>();
  NotaryServiceImpl service(authorizer);
  EXPECT_THROW(static_cast<void>(StartNotaryServer(config, &service)),
               std::runtime_error);
}

}  // namespace
}  // namespace veritas::notary
