#include "signer.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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

KeyCertPair GenerateSelfSigned() {
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
  const unsigned char cn[] = "veritas-notary-test";
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
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
            ("veritas_notary_signer_test_" +
             std::to_string(std::chrono::steady_clock::now()
                                .time_since_epoch()
                                .count()));
    std::filesystem::create_directories(path_);
  }

  ~TempDir() { std::error_code ec; std::filesystem::remove_all(path_, ec); }

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

TEST(SignerTest, ValidateSignerKeyMaterialAcceptsMatchingPair) {
  TempDir temp;
  const auto pair = GenerateSelfSigned();

  const auto cert_path = temp.path() / "issuer.crt";
  const auto key_path = temp.path() / "issuer.key";
  WriteFile(cert_path, pair.cert_pem);
  WriteFile(key_path, pair.key_pem);

  SignerConfig config;
  config.issuer_cert_path = cert_path.string();
  config.issuer_key_path = key_path.string();
  EXPECT_NO_THROW(ValidateSignerKeyMaterial(config));
}

TEST(SignerTest, ValidateSignerKeyMaterialRejectsMissingPaths) {
  SignerConfig config;
  EXPECT_THROW(ValidateSignerKeyMaterial(config), SignerConfigError);
}

TEST(SignerTest, ValidateSignerKeyMaterialRejectsInvalidPem) {
  TempDir temp;
  const auto cert_path = temp.path() / "issuer.crt";
  const auto key_path = temp.path() / "issuer.key";
  WriteFile(cert_path, "not-a-certificate");
  WriteFile(key_path, "not-a-private-key");

  SignerConfig config;
  config.issuer_cert_path = cert_path.string();
  config.issuer_key_path = key_path.string();
  EXPECT_THROW(ValidateSignerKeyMaterial(config), SignerConfigError);
}

TEST(SignerTest, ValidateSignerKeyMaterialRejectsMismatchedKey) {
  TempDir temp;
  const auto pair_one = GenerateSelfSigned();
  const auto pair_two = GenerateSelfSigned();

  const auto cert_path = temp.path() / "issuer.crt";
  const auto key_path = temp.path() / "issuer.key";
  WriteFile(cert_path, pair_one.cert_pem);
  WriteFile(key_path, pair_two.key_pem);

  SignerConfig config;
  config.issuer_cert_path = cert_path.string();
  config.issuer_key_path = key_path.string();

  try {
    ValidateSignerKeyMaterial(config);
    FAIL() << "expected key/certificate mismatch";
  } catch (const SignerConfigError& ex) {
    EXPECT_EQ(ex.code(), SignerConfigErrorCode::KeyCertificateMismatch);
  }
}

TEST(SignerTest, OpenSslSignerConstructorValidatesMaterial) {
  SignerConfig config;
  config.issuer_cert_path = "/nonexistent/cert.pem";
  config.issuer_key_path = "/nonexistent/key.pem";
  EXPECT_THROW(
      {
        OpenSslSigner signer(config);
        static_cast<void>(signer);
      },
      SignerConfigError);
}

TEST(SignerTest, OpenSslSignerIssueIsExplicitPlaceholder) {
  TempDir temp;
  const auto pair = GenerateSelfSigned();

  const auto cert_path = temp.path() / "issuer.crt";
  const auto key_path = temp.path() / "issuer.key";
  WriteFile(cert_path, pair.cert_pem);
  WriteFile(key_path, pair.key_pem);

  SignerConfig config;
  config.issuer_cert_path = cert_path.string();
  config.issuer_key_path = key_path.string();
  OpenSslSigner signer(config);

  SigningRequest request;
  request.requested_ttl = std::chrono::minutes(30);
  EXPECT_THROW(static_cast<void>(signer.Issue(request)), std::runtime_error);
}

}  // namespace
}  // namespace veritas::notary
