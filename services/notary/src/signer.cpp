#include "signer.h"

#include <memory>

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

std::unique_ptr<BIO, BioDeleter> OpenFileBio(
    const std::string& path, SignerConfigErrorCode error_code,
    const std::string& message) {
  std::unique_ptr<BIO, BioDeleter> bio(BIO_new_file(path.c_str(), "r"));
  if (!bio) {
    throw SignerConfigError(error_code, message + ": " + path);
  }
  return bio;
}

}  // namespace

SignerConfigError::SignerConfigError(SignerConfigErrorCode code,
                                     const std::string& message)
    : std::runtime_error(message), code_(code) {}

SignerConfigErrorCode SignerConfigError::code() const noexcept { return code_; }

void ValidateSignerKeyMaterial(const SignerConfig& config) {
  if (config.issuer_cert_path.empty()) {
    throw SignerConfigError(SignerConfigErrorCode::MissingIssuerCertificatePath,
                            "issuer certificate path is required");
  }
  if (config.issuer_key_path.empty()) {
    throw SignerConfigError(SignerConfigErrorCode::MissingIssuerPrivateKeyPath,
                            "issuer private key path is required");
  }

  auto cert_bio =
      OpenFileBio(config.issuer_cert_path,
                  SignerConfigErrorCode::UnreadableIssuerCertificate,
                  "failed to read issuer certificate");
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    throw SignerConfigError(SignerConfigErrorCode::InvalidIssuerCertificate,
                            "failed to parse issuer certificate");
  }

  auto key_bio = OpenFileBio(config.issuer_key_path,
                             SignerConfigErrorCode::UnreadableIssuerPrivateKey,
                             "failed to read issuer private key");
  std::unique_ptr<EVP_PKEY, PkeyDeleter> key(
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    throw SignerConfigError(SignerConfigErrorCode::InvalidIssuerPrivateKey,
                            "failed to parse issuer private key");
  }

  if (X509_check_private_key(cert.get(), key.get()) != 1) {
    throw SignerConfigError(SignerConfigErrorCode::KeyCertificateMismatch,
                            "issuer private key does not match certificate");
  }
}

OpenSslSigner::OpenSslSigner(SignerConfig config) : config_(std::move(config)) {
  ValidateSignerKeyMaterial(config_);
}

const SignerConfig& OpenSslSigner::config() const noexcept { return config_; }

SigningResult OpenSslSigner::Issue(const SigningRequest& /*request*/) {
  throw std::runtime_error("OpenSslSigner::Issue is not implemented");
}

}  // namespace veritas::notary
