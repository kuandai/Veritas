#include "tls_utils.h"

#include <memory>
#include <stdexcept>

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

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

std::unique_ptr<X509, X509Deleter> LoadCertificate(const std::string& pem) {
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate cert BIO");
  }
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    throw std::runtime_error("Invalid TLS certificate PEM");
  }
  return cert;
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> LoadPrivateKey(const std::string& pem) {
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate key BIO");
  }
  std::unique_ptr<EVP_PKEY, PkeyDeleter> key(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    throw std::runtime_error("Invalid TLS private key PEM");
  }
  return key;
}

void ValidateOptionalBundle(const std::string& ca_bundle_pem) {
  if (ca_bundle_pem.empty()) {
    return;
  }

  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(ca_bundle_pem.data(), static_cast<int>(ca_bundle_pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate CA bundle BIO");
  }

  bool saw_cert = false;
  while (true) {
    X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) {
      break;
    }
    saw_cert = true;
    X509_free(raw);
  }

  if (!saw_cert) {
    throw std::runtime_error("TLS CA bundle does not contain any certificate");
  }
}

}  // namespace

void ValidateServerTlsCredentials(const std::string& cert_pem,
                                  const std::string& key_pem,
                                  const std::string& ca_bundle_pem) {
  auto cert = LoadCertificate(cert_pem);
  auto key = LoadPrivateKey(key_pem);
  if (X509_check_private_key(cert.get(), key.get()) != 1) {
    throw std::runtime_error("TLS private key does not match certificate");
  }

  if (X509_cmp_current_time(X509_get_notBefore(cert.get())) > 0) {
    throw std::runtime_error("TLS certificate is not yet valid");
  }
  if (X509_cmp_current_time(X509_get_notAfter(cert.get())) < 0) {
    throw std::runtime_error("TLS certificate has expired");
  }

  ValidateOptionalBundle(ca_bundle_pem);
}

}  // namespace veritas::notary
