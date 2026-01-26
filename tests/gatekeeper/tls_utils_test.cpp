#include "tls_utils.h"

#include <chrono>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace veritas::gatekeeper {
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

KeyCertPair GenerateSelfSigned(long not_before_offset_sec,
                               long not_after_offset_sec) {
  auto key = GenerateKey();
  std::unique_ptr<X509, X509Deleter> cert(X509_new());
  if (!cert) {
    throw std::runtime_error("Failed to allocate X509");
  }
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), not_before_offset_sec);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), not_after_offset_sec);
  X509_set_pubkey(cert.get(), key.get());

  X509_NAME* name = X509_get_subject_name(cert.get());
  const unsigned char cn[] = "veritas-test";
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

  KeyCertPair result;
  result.key_pem = BioToString(key_bio.get());
  result.cert_pem = BioToString(cert_bio.get());
  return result;
}

}  // namespace

TEST(TlsUtilsTest, AcceptsSelfSignedWithBundle) {
  const auto pair = GenerateSelfSigned(-60, 60 * 60);
  EXPECT_NO_THROW(ValidateTlsCredentials(pair.cert_pem, pair.key_pem,
                                         pair.cert_pem));
}

TEST(TlsUtilsTest, RejectsMismatchedKey) {
  const auto pair = GenerateSelfSigned(-60, 60 * 60);
  const auto other_key = GenerateSelfSigned(-60, 60 * 60).key_pem;
  EXPECT_THROW(ValidateTlsCredentials(pair.cert_pem, other_key, ""),
               std::runtime_error);
}

TEST(TlsUtilsTest, RejectsNotYetValidCertificate) {
  const auto pair = GenerateSelfSigned(60 * 60, 2 * 60 * 60);
  EXPECT_THROW(ValidateTlsCredentials(pair.cert_pem, pair.key_pem, ""),
               std::runtime_error);
}

TEST(TlsUtilsTest, RejectsExpiredCertificate) {
  const auto pair = GenerateSelfSigned(-2 * 60 * 60, -60 * 60);
  EXPECT_THROW(ValidateTlsCredentials(pair.cert_pem, pair.key_pem, ""),
               std::runtime_error);
}

TEST(TlsUtilsTest, RejectsInvalidChain) {
  const auto leaf = GenerateSelfSigned(-60, 60 * 60);
  const auto other_ca = GenerateSelfSigned(-60, 60 * 60);
  EXPECT_THROW(ValidateTlsCredentials(leaf.cert_pem, leaf.key_pem,
                                      other_ca.cert_pem),
               std::runtime_error);
}

TEST(TlsUtilsTest, RejectsInvalidPem) {
  const auto key = GenerateSelfSigned(-60, 60 * 60).key_pem;
  EXPECT_THROW(ValidateTlsCredentials("not-a-cert", key, ""),
               std::runtime_error);
}

}  // namespace veritas::gatekeeper
