#include "signer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <vector>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

struct X509ReqDeleter {
  void operator()(X509_REQ* req) const { X509_REQ_free(req); }
};

struct BnDeleter {
  void operator()(BIGNUM* bn) const { BN_free(bn); }
};

struct Asn1IntegerDeleter {
  void operator()(ASN1_INTEGER* integer) const { ASN1_INTEGER_free(integer); }
};

struct ExtensionsDeleter {
  void operator()(STACK_OF(X509_EXTENSION)* exts) const {
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  }
};

struct GeneralNamesDeleter {
  void operator()(GENERAL_NAMES* names) const { GENERAL_NAMES_free(names); }
};

constexpr auto kMinimumTtl = std::chrono::seconds(std::chrono::minutes(1));
constexpr auto kMaximumTtl = std::chrono::seconds(std::chrono::hours(24));
constexpr auto kNotBeforeSkew = std::chrono::seconds(60);

std::unique_ptr<BIO, BioDeleter> OpenFileBio(
    const std::string& path, SignerConfigErrorCode error_code,
    const std::string& message) {
  std::unique_ptr<BIO, BioDeleter> bio(BIO_new_file(path.c_str(), "rb"));
  if (!bio) {
    throw SignerConfigError(error_code, message + ": " + path);
  }
  return bio;
}

std::string ReadTextFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to read issuer chain file");
  }
  std::ostringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

std::unique_ptr<X509, X509Deleter> LoadIssuerCertificate(
    const std::string& path) {
  auto cert_bio =
      OpenFileBio(path, SignerConfigErrorCode::UnreadableIssuerCertificate,
                  "failed to read issuer certificate");
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to parse issuer certificate");
  }
  return cert;
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> LoadIssuerPrivateKey(
    const std::string& path) {
  auto key_bio =
      OpenFileBio(path, SignerConfigErrorCode::UnreadableIssuerPrivateKey,
                  "failed to read issuer private key");
  std::unique_ptr<EVP_PKEY, PkeyDeleter> key(
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to parse issuer private key");
  }
  return key;
}

std::unique_ptr<X509, X509Deleter> ParseCertificatePem(
    const std::string& certificate_pem) {
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(certificate_pem.data(),
                      static_cast<int>(certificate_pem.size())));
  if (!bio) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "invalid certificate PEM buffer");
  }
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "failed to parse certificate PEM");
  }
  return cert;
}

std::chrono::seconds ClampRequestedTtl(std::chrono::seconds requested_ttl) {
  if (requested_ttl < kMinimumTtl) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "requested_ttl is below minimum policy bound");
  }
  return std::min(requested_ttl, kMaximumTtl);
}

std::unique_ptr<X509_REQ, X509ReqDeleter> ParseCsrDer(
    const std::string& csr_der) {
  const unsigned char* cursor =
      reinterpret_cast<const unsigned char*>(csr_der.data());
  const unsigned char* end = cursor + csr_der.size();
  std::unique_ptr<X509_REQ, X509ReqDeleter> req(
      d2i_X509_REQ(nullptr, &cursor, static_cast<long>(csr_der.size())));
  if (!req || cursor != end) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "invalid csr_der payload");
  }

  std::unique_ptr<EVP_PKEY, PkeyDeleter> csr_key(X509_REQ_get_pubkey(req.get()));
  if (!csr_key || X509_REQ_verify(req.get(), csr_key.get()) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "CSR signature verification failed");
  }
  return req;
}

std::optional<std::string> ExtractCommonName(X509_NAME* subject_name) {
  const int cn_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
  if (cn_index < 0) {
    return std::nullopt;
  }
  X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, cn_index);
  ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
  unsigned char* utf8 = nullptr;
  const int length = ASN1_STRING_to_UTF8(&utf8, data);
  if (length < 0) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "invalid subject common name");
  }
  std::string common_name(reinterpret_cast<char*>(utf8),
                          static_cast<size_t>(length));
  OPENSSL_free(utf8);
  return common_name;
}

void ValidateSubjectAltNamePolicy(X509_REQ* csr) {
  std::unique_ptr<STACK_OF(X509_EXTENSION), ExtensionsDeleter> exts(
      X509_REQ_get_extensions(csr));
  if (!exts) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "CSR SAN extension is required");
  }

  bool found_san = false;
  std::vector<std::string> dns_names;
  for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i) {
    X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts.get(), i);
    if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name) {
      continue;
    }

    found_san = true;
    std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter> names(
        static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext)));
    if (!names) {
      throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                             "failed to parse CSR SAN extension");
    }

    const int name_count = sk_GENERAL_NAME_num(names.get());
    if (name_count == 0) {
      throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                             "CSR SAN extension cannot be empty");
    }
    for (int n = 0; n < name_count; ++n) {
      GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), n);
      if (name->type == GEN_DNS) {
        const auto* dns = name->d.dNSName;
        dns_names.emplace_back(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(dns)),
            static_cast<size_t>(ASN1_STRING_length(dns)));
      } else if (name->type == GEN_IPADD) {
        continue;
      } else {
        throw SignerIssueError(
            SignerIssueErrorCode::PolicyDenied,
            "unsupported SAN type in CSR (only DNS/IP are allowed)");
      }
    }
  }

  if (!found_san) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "CSR SAN extension is required");
  }

  const auto common_name = ExtractCommonName(X509_REQ_get_subject_name(csr));
  if (common_name.has_value() && !dns_names.empty() &&
      std::find(dns_names.begin(), dns_names.end(), *common_name) ==
          dns_names.end()) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "subject CN must match one of DNS SAN entries");
  }
}

void ValidateSubjectAltNamePolicy(X509* certificate) {
  std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter> names(
      static_cast<GENERAL_NAMES*>(
          X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)));
  if (!names) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "certificate SAN extension is required");
  }

  std::vector<std::string> dns_names;
  const int name_count = sk_GENERAL_NAME_num(names.get());
  if (name_count == 0) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "certificate SAN extension cannot be empty");
  }
  for (int n = 0; n < name_count; ++n) {
    GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), n);
    if (name->type == GEN_DNS) {
      const auto* dns = name->d.dNSName;
      dns_names.emplace_back(
          reinterpret_cast<const char*>(ASN1_STRING_get0_data(dns)),
          static_cast<size_t>(ASN1_STRING_length(dns)));
    } else if (name->type == GEN_IPADD) {
      continue;
    } else {
      throw SignerIssueError(
          SignerIssueErrorCode::PolicyDenied,
          "unsupported SAN type in certificate (only DNS/IP are allowed)");
    }
  }

  const auto common_name =
      ExtractCommonName(X509_get_subject_name(certificate));
  if (common_name.has_value() && !dns_names.empty() &&
      std::find(dns_names.begin(), dns_names.end(), *common_name) ==
          dns_names.end()) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "subject CN must match one of DNS SAN entries");
  }
}

void ValidateKeyPolicy(EVP_PKEY* pubkey, const char* error_context) {
  if (!pubkey) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           std::string(error_context) + " public key is missing");
  }

  const int key_type = EVP_PKEY_base_id(pubkey);
  const int key_bits = EVP_PKEY_bits(pubkey);
  if (key_type == EVP_PKEY_RSA) {
    if (key_bits < 2048) {
      throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                             "RSA key size below policy minimum");
    }
    return;
  }
  if (key_type == EVP_PKEY_EC) {
    if (key_bits < 256) {
      throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                             "EC key size below policy minimum");
    }
    return;
  }
  throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                         "unsupported key type");
}

void ValidateKeyPolicy(X509_REQ* csr) {
  std::unique_ptr<EVP_PKEY, PkeyDeleter> pubkey(X509_REQ_get_pubkey(csr));
  ValidateKeyPolicy(pubkey.get(), "CSR");
}

void ValidateKeyPolicy(X509* certificate) {
  std::unique_ptr<EVP_PKEY, PkeyDeleter> pubkey(X509_get_pubkey(certificate));
  ValidateKeyPolicy(pubkey.get(), "certificate");
}

void AddExtension(X509* certificate, X509* issuer, int nid,
                  const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer, certificate, nullptr, nullptr, 0);
  X509V3_set_ctx_nodb(&ctx);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(
      nullptr, &ctx, nid, const_cast<char*>(value));
  if (!ext) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to create certificate extension");
  }
  if (X509_add_ext(certificate, ext, -1) != 1) {
    X509_EXTENSION_free(ext);
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to add certificate extension");
  }
  X509_EXTENSION_free(ext);
}

void CopySanExtensionFromCsr(X509_REQ* csr, X509* certificate) {
  std::unique_ptr<STACK_OF(X509_EXTENSION), ExtensionsDeleter> exts(
      X509_REQ_get_extensions(csr));
  if (!exts) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "CSR SAN extension is required");
  }

  bool copied = false;
  for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i) {
    X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts.get(), i);
    if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name) {
      continue;
    }
    X509_EXTENSION* duplicate = X509_EXTENSION_dup(ext);
    if (!duplicate) {
      throw SignerIssueError(SignerIssueErrorCode::Internal,
                             "failed to duplicate SAN extension");
    }
    if (X509_add_ext(certificate, duplicate, -1) != 1) {
      X509_EXTENSION_free(duplicate);
      throw SignerIssueError(SignerIssueErrorCode::Internal,
                             "failed to copy SAN extension to certificate");
    }
    X509_EXTENSION_free(duplicate);
    copied = true;
  }

  if (!copied) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "CSR SAN extension is required");
  }
}

void CopySanExtensionFromCertificate(X509* source, X509* certificate) {
  bool copied = false;
  const int ext_count = X509_get_ext_count(source);
  for (int i = 0; i < ext_count; ++i) {
    X509_EXTENSION* ext = X509_get_ext(source, i);
    if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name) {
      continue;
    }
    X509_EXTENSION* duplicate = X509_EXTENSION_dup(ext);
    if (!duplicate) {
      throw SignerIssueError(SignerIssueErrorCode::Internal,
                             "failed to duplicate SAN extension");
    }
    if (X509_add_ext(certificate, duplicate, -1) != 1) {
      X509_EXTENSION_free(duplicate);
      throw SignerIssueError(SignerIssueErrorCode::Internal,
                             "failed to copy SAN extension to certificate");
    }
    X509_EXTENSION_free(duplicate);
    copied = true;
  }
  if (!copied) {
    throw SignerIssueError(SignerIssueErrorCode::PolicyDenied,
                           "certificate SAN extension is required");
  }
}

std::string GenerateAndSetSerial(X509* certificate) {
  std::array<unsigned char, 16> serial_bytes{};
  if (RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to generate certificate serial");
  }
  serial_bytes[0] &= 0x7f;

  std::unique_ptr<BIGNUM, BnDeleter> bn(
      BN_bin2bn(serial_bytes.data(), static_cast<int>(serial_bytes.size()), nullptr));
  if (!bn) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to allocate serial bignum");
  }
  std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter> asn1(
      BN_to_ASN1_INTEGER(bn.get(), nullptr));
  if (!asn1 || X509_set_serialNumber(certificate, asn1.get()) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set certificate serial");
  }

  char* hex = BN_bn2hex(bn.get());
  if (!hex) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to encode serial");
  }
  std::string serial(hex);
  OPENSSL_free(hex);
  return serial;
}

std::string X509ToPem(X509* cert) {
  std::unique_ptr<BIO, BioDeleter> bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to encode certificate PEM");
  }
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  if (!mem || !mem->data || mem->length == 0) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "empty certificate PEM output");
  }
  return std::string(mem->data, mem->length);
}

}  // namespace

SignerConfigError::SignerConfigError(SignerConfigErrorCode code,
                                     const std::string& message)
    : std::runtime_error(message), code_(code) {}

SignerConfigErrorCode SignerConfigError::code() const noexcept { return code_; }

SignerIssueError::SignerIssueError(SignerIssueErrorCode code,
                                   const std::string& message)
    : std::runtime_error(message), code_(code) {}

SignerIssueErrorCode SignerIssueError::code() const noexcept { return code_; }

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

SigningResult OpenSslSigner::Issue(const SigningRequest& request) {
  if (request.csr_der.empty()) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "csr_der is required");
  }

  const auto ttl = ClampRequestedTtl(request.requested_ttl);

  auto issuer_cert = LoadIssuerCertificate(config_.issuer_cert_path);
  auto issuer_key = LoadIssuerPrivateKey(config_.issuer_key_path);
  auto csr = ParseCsrDer(request.csr_der);

  ValidateSubjectAltNamePolicy(csr.get());
  ValidateKeyPolicy(csr.get());

  std::unique_ptr<X509, X509Deleter> leaf(X509_new());
  if (!leaf) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to allocate output certificate");
  }
  if (X509_set_version(leaf.get(), 2) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set certificate version");
  }

  const std::string serial = GenerateAndSetSerial(leaf.get());
  if (X509_set_issuer_name(leaf.get(), X509_get_subject_name(issuer_cert.get())) !=
          1 ||
      X509_set_subject_name(leaf.get(), X509_REQ_get_subject_name(csr.get())) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set certificate names");
  }

  std::unique_ptr<EVP_PKEY, PkeyDeleter> subject_key(X509_REQ_get_pubkey(csr.get()));
  if (!subject_key || X509_set_pubkey(leaf.get(), subject_key.get()) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "failed to extract CSR public key");
  }

  const auto now = std::chrono::system_clock::now();
  const auto not_before = now - kNotBeforeSkew;
  const auto not_after = now + ttl;
  if (!X509_gmtime_adj(X509_getm_notBefore(leaf.get()),
                       -static_cast<long>(kNotBeforeSkew.count())) ||
      !X509_gmtime_adj(X509_getm_notAfter(leaf.get()),
                       static_cast<long>(ttl.count()))) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set certificate validity");
  }

  AddExtension(leaf.get(), issuer_cert.get(), NID_basic_constraints,
               "critical,CA:FALSE");
  AddExtension(leaf.get(), issuer_cert.get(), NID_key_usage,
               "critical,digitalSignature,keyEncipherment");
  AddExtension(leaf.get(), issuer_cert.get(), NID_ext_key_usage,
               "clientAuth,serverAuth");
  CopySanExtensionFromCsr(csr.get(), leaf.get());

  if (X509_sign(leaf.get(), issuer_key.get(), EVP_sha256()) <= 0) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to sign certificate");
  }

  SigningResult result;
  result.certificate_serial = serial;
  result.certificate_pem = X509ToPem(leaf.get());
  if (!config_.issuer_chain_path.empty()) {
    result.certificate_chain_pem = ReadTextFile(config_.issuer_chain_path);
  }
  result.not_before = not_before;
  result.not_after = not_after;
  return result;
}

SigningResult OpenSslSigner::Renew(const RenewalSigningRequest& request) {
  if (request.certificate_pem.empty()) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "certificate_pem is required for renewal");
  }

  const auto ttl = ClampRequestedTtl(request.requested_ttl);
  auto issuer_cert = LoadIssuerCertificate(config_.issuer_cert_path);
  auto issuer_key = LoadIssuerPrivateKey(config_.issuer_key_path);
  auto current_leaf = ParseCertificatePem(request.certificate_pem);

  ValidateSubjectAltNamePolicy(current_leaf.get());
  ValidateKeyPolicy(current_leaf.get());

  std::unique_ptr<X509, X509Deleter> renewed_leaf(X509_new());
  if (!renewed_leaf) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to allocate renewed certificate");
  }
  if (X509_set_version(renewed_leaf.get(), 2) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set certificate version");
  }

  const std::string serial = GenerateAndSetSerial(renewed_leaf.get());
  if (X509_set_issuer_name(renewed_leaf.get(),
                           X509_get_subject_name(issuer_cert.get())) != 1 ||
      X509_set_subject_name(renewed_leaf.get(),
                            X509_get_subject_name(current_leaf.get())) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set renewal certificate names");
  }

  std::unique_ptr<EVP_PKEY, PkeyDeleter> subject_key(
      X509_get_pubkey(current_leaf.get()));
  if (!subject_key ||
      X509_set_pubkey(renewed_leaf.get(), subject_key.get()) != 1) {
    throw SignerIssueError(SignerIssueErrorCode::InvalidRequest,
                           "failed to extract certificate public key");
  }

  const auto now = std::chrono::system_clock::now();
  const auto not_before = now - kNotBeforeSkew;
  const auto not_after = now + ttl;
  if (!X509_gmtime_adj(X509_getm_notBefore(renewed_leaf.get()),
                       -static_cast<long>(kNotBeforeSkew.count())) ||
      !X509_gmtime_adj(X509_getm_notAfter(renewed_leaf.get()),
                       static_cast<long>(ttl.count()))) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to set renewal certificate validity");
  }

  AddExtension(renewed_leaf.get(), issuer_cert.get(), NID_basic_constraints,
               "critical,CA:FALSE");
  AddExtension(renewed_leaf.get(), issuer_cert.get(), NID_key_usage,
               "critical,digitalSignature,keyEncipherment");
  AddExtension(renewed_leaf.get(), issuer_cert.get(), NID_ext_key_usage,
               "clientAuth,serverAuth");
  CopySanExtensionFromCertificate(current_leaf.get(), renewed_leaf.get());

  if (X509_sign(renewed_leaf.get(), issuer_key.get(), EVP_sha256()) <= 0) {
    throw SignerIssueError(SignerIssueErrorCode::Internal,
                           "failed to sign renewed certificate");
  }

  SigningResult result;
  result.certificate_serial = serial;
  result.certificate_pem = X509ToPem(renewed_leaf.get());
  if (!config_.issuer_chain_path.empty()) {
    result.certificate_chain_pem = ReadTextFile(config_.issuer_chain_path);
  }
  result.not_before = not_before;
  result.not_after = not_after;
  return result;
}

}  // namespace veritas::notary
