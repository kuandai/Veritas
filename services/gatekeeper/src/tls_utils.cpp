#include "tls_utils.h"

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace veritas::gatekeeper {

namespace {

struct BioDeleter {
  void operator()(BIO* bio) const { BIO_free(bio); }
};

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

struct StoreDeleter {
  void operator()(X509_STORE* store) const { X509_STORE_free(store); }
};

struct StoreCtxDeleter {
  void operator()(X509_STORE_CTX* ctx) const { X509_STORE_CTX_free(ctx); }
};

struct StackDeleter {
  void operator()(STACK_OF(X509)* stack) const {
    sk_X509_pop_free(stack, X509_free);
  }
};

std::vector<std::unique_ptr<X509, X509Deleter>> LoadCertificates(
    const std::string& pem) {
  std::vector<std::unique_ptr<X509, X509Deleter>> certs;
  if (pem.empty()) {
    return certs;
  }

  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate BIO for certificate bundle");
  }

  while (true) {
    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
      break;
    }
    certs.emplace_back(cert);
  }

  return certs;
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> LoadPrivateKey(
    const std::string& pem) {
  if (pem.empty()) {
    throw std::runtime_error("TLS private key is empty");
  }
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate BIO for private key");
  }
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (!key) {
    throw std::runtime_error("Failed to parse TLS private key");
  }
  return std::unique_ptr<EVP_PKEY, PkeyDeleter>(key);
}

void VerifyValidityWindow(X509* cert) {
  if (!cert) {
    throw std::runtime_error("Missing TLS certificate");
  }
  if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) {
    throw std::runtime_error("TLS certificate is not yet valid");
  }
  if (X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {
    throw std::runtime_error("TLS certificate has expired");
  }
}

void VerifyChainWithBundle(
    X509* leaf,
    const std::vector<std::unique_ptr<X509, X509Deleter>>& chain,
    const std::string& ca_bundle_pem) {
  auto ca_certs = LoadCertificates(ca_bundle_pem);
  if (ca_certs.empty()) {
    throw std::runtime_error("TLS CA bundle is empty or invalid");
  }

  std::unique_ptr<X509_STORE, StoreDeleter> store(X509_STORE_new());
  if (!store) {
    throw std::runtime_error("Failed to create X509 store");
  }

  for (const auto& ca_cert : ca_certs) {
    if (X509_STORE_add_cert(store.get(), ca_cert.get()) != 1) {
      throw std::runtime_error("Failed to add CA certificate to store");
    }
  }

  std::unique_ptr<STACK_OF(X509), StackDeleter> untrusted(
      sk_X509_new_null());
  if (!untrusted) {
    throw std::runtime_error("Failed to allocate certificate chain stack");
  }

  for (size_t i = 1; i < chain.size(); ++i) {
    X509* dup = X509_dup(chain[i].get());
    if (!dup) {
      throw std::runtime_error("Failed to duplicate intermediate certificate");
    }
    if (sk_X509_push(untrusted.get(), dup) == 0) {
      X509_free(dup);
      throw std::runtime_error("Failed to append intermediate certificate");
    }
  }

  std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter> ctx(
      X509_STORE_CTX_new());
  if (!ctx) {
    throw std::runtime_error("Failed to allocate X509 store context");
  }

  if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf, untrusted.get()) != 1) {
    throw std::runtime_error("Failed to initialize X509 store context");
  }

  const int verify_result = X509_verify_cert(ctx.get());
  if (verify_result != 1) {
    const int err = X509_STORE_CTX_get_error(ctx.get());
    const char* reason = X509_verify_cert_error_string(err);
    std::string message = "TLS certificate chain validation failed";
    if (reason) {
      message += ": ";
      message += reason;
    }
    throw std::runtime_error(message);
  }
}

}  // namespace

void ValidateTlsCredentials(const std::string& cert_chain_pem,
                            const std::string& key_pem,
                            const std::string& ca_bundle_pem) {
  auto chain = LoadCertificates(cert_chain_pem);
  if (chain.empty()) {
    throw std::runtime_error("TLS certificate chain is empty or invalid");
  }

  auto private_key = LoadPrivateKey(key_pem);
  X509* leaf = chain.front().get();

  if (X509_check_private_key(leaf, private_key.get()) != 1) {
    throw std::runtime_error("TLS private key does not match certificate");
  }

  VerifyValidityWindow(leaf);

  if (!ca_bundle_pem.empty()) {
    VerifyChainWithBundle(leaf, chain, ca_bundle_pem);
  }
}

}  // namespace veritas::gatekeeper
