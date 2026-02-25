#include "signer.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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

struct PkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

struct X509ReqDeleter {
  void operator()(X509_REQ* req) const { X509_REQ_free(req); }
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

std::string ExtractCertificateCommonName(const std::string& certificate_pem) {
  std::unique_ptr<BIO, BioDeleter> bio(
      BIO_new_mem_buf(certificate_pem.data(),
                      static_cast<int>(certificate_pem.size())));
  if (!bio) {
    throw std::runtime_error("Failed to allocate certificate BIO");
  }

  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    throw std::runtime_error("Failed to parse certificate PEM");
  }

  X509_NAME* subject = X509_get_subject_name(cert.get());
  if (!subject) {
    throw std::runtime_error("Certificate subject is missing");
  }

  const int cn_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
  if (cn_index < 0) {
    return {};
  }
  X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, cn_index);
  ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
  unsigned char* utf8 = nullptr;
  const int length = ASN1_STRING_to_UTF8(&utf8, data);
  if (length < 0) {
    throw std::runtime_error("Failed to decode certificate subject CN");
  }
  std::string cn(reinterpret_cast<char*>(utf8), static_cast<size_t>(length));
  OPENSSL_free(utf8);
  return cn;
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> GenerateRsaKey(int bits) {
  std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx) {
    throw std::runtime_error("Failed to create keygen context");
  }
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to init keygen");
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
    throw std::runtime_error("Failed to set key size");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
    throw std::runtime_error("Failed to generate key");
  }
  return std::unique_ptr<EVP_PKEY, PkeyDeleter>(pkey);
}

KeyCertPair GenerateSelfSignedIssuer() {
  auto key = GenerateRsaKey(2048);
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
  const unsigned char cn[] = "veritas-notary-test-issuer";
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
    throw std::runtime_error("Failed to sign issuer certificate");
  }

  std::unique_ptr<BIO, BioDeleter> key_bio(BIO_new(BIO_s_mem()));
  std::unique_ptr<BIO, BioDeleter> cert_bio(BIO_new(BIO_s_mem()));
  if (!key_bio || !cert_bio) {
    throw std::runtime_error("Failed to allocate BIO");
  }
  if (PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0,
                               nullptr, nullptr) != 1) {
    throw std::runtime_error("Failed to write issuer private key");
  }
  if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
    throw std::runtime_error("Failed to write issuer certificate");
  }

  return KeyCertPair{BioToString(key_bio.get()), BioToString(cert_bio.get())};
}

std::string JoinSanSpec(const std::vector<std::string>& dns_names,
                        bool include_email) {
  std::string spec;
  for (const auto& dns_name : dns_names) {
    if (!spec.empty()) {
      spec += ",";
    }
    spec += "DNS:";
    spec += dns_name;
  }
  if (include_email) {
    if (!spec.empty()) {
      spec += ",";
    }
    spec += "email:security@example.com";
  }
  return spec;
}

std::string GenerateCsrDer(const std::string& common_name,
                           const std::vector<std::string>& dns_names,
                           int key_bits = 2048,
                           bool include_email = false) {
  auto key = GenerateRsaKey(key_bits);
  std::unique_ptr<X509_REQ, X509ReqDeleter> req(X509_REQ_new());
  if (!req) {
    throw std::runtime_error("Failed to allocate CSR");
  }

  if (X509_REQ_set_version(req.get(), 0L) != 1) {
    throw std::runtime_error("Failed to set CSR version");
  }
  X509_NAME* subject_name = X509_REQ_get_subject_name(req.get());
  if (!common_name.empty()) {
    X509_NAME_add_entry_by_txt(
        subject_name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(common_name.c_str()), -1, -1, 0);
  }
  if (X509_REQ_set_pubkey(req.get(), key.get()) != 1) {
    throw std::runtime_error("Failed to set CSR public key");
  }

  const auto san_spec = JoinSanSpec(dns_names, include_email);
  if (!san_spec.empty()) {
    X509_EXTENSION* san_ext = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name,
        const_cast<char*>(san_spec.c_str()));
    if (!san_ext) {
      throw std::runtime_error("Failed to create SAN extension");
    }
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    if (!exts || sk_X509_EXTENSION_push(exts, san_ext) != 1) {
      if (exts) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
      } else {
        X509_EXTENSION_free(san_ext);
      }
      throw std::runtime_error("Failed to build CSR extension stack");
    }
    if (X509_REQ_add_extensions(req.get(), exts) != 1) {
      sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
      throw std::runtime_error("Failed to add CSR extensions");
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  }

  if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) <= 0) {
    throw std::runtime_error("Failed to sign CSR");
  }

  const int der_length = i2d_X509_REQ(req.get(), nullptr);
  if (der_length <= 0) {
    throw std::runtime_error("Failed to get CSR DER length");
  }

  std::string der(static_cast<size_t>(der_length), '\0');
  unsigned char* out =
      reinterpret_cast<unsigned char*>(der.data());
  if (i2d_X509_REQ(req.get(), &out) <= 0) {
    throw std::runtime_error("Failed to encode CSR DER");
  }
  return der;
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

SignerConfig BuildSignerConfig(const TempDir& temp, const KeyCertPair& pair,
                               bool with_chain = false) {
  const auto cert_path = temp.path() / "issuer.crt";
  const auto key_path = temp.path() / "issuer.key";
  WriteFile(cert_path, pair.cert_pem);
  WriteFile(key_path, pair.key_pem);

  SignerConfig config;
  config.issuer_cert_path = cert_path.string();
  config.issuer_key_path = key_path.string();
  if (with_chain) {
    const auto chain_path = temp.path() / "issuer-chain.pem";
    WriteFile(chain_path, "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n");
    config.issuer_chain_path = chain_path.string();
  }
  return config;
}

TEST(SignerTest, ValidateSignerKeyMaterialAcceptsMatchingPair) {
  TempDir temp;
  const auto pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, pair);
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
  const auto pair_one = GenerateSelfSignedIssuer();
  const auto pair_two = GenerateSelfSignedIssuer();

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

TEST(SignerTest, OpenSslSignerIssuesCertificateAndReturnsChain) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair, true);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = GenerateCsrDer(
      "svc.example.internal",
      {"svc.example.internal", "svc-alt.example.internal"});
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::minutes(30);

  const auto result = signer.Issue(request);
  EXPECT_FALSE(result.certificate_serial.empty());
  EXPECT_FALSE(result.certificate_pem.empty());
  EXPECT_FALSE(result.certificate_chain_pem.empty());
  EXPECT_LT(result.not_before, result.not_after);
  EXPECT_EQ(ExtractCertificateCommonName(result.certificate_pem),
            "principal-user");
}

TEST(SignerTest, OpenSslSignerRejectsMalformedCsr) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = "not-der";
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Issue(request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::InvalidRequest);
  }
}

TEST(SignerTest, OpenSslSignerRejectsMissingAuthoritativeSubject) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = GenerateCsrDer("svc.example.internal",
                                   {"svc.example.internal"});
  request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Issue(request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::InvalidRequest);
  }
}

TEST(SignerTest, OpenSslSignerRejectsMissingSan) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = GenerateCsrDer("svc.example.internal", {});
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Issue(request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::PolicyDenied);
  }
}

TEST(SignerTest, OpenSslSignerRejectsUnsupportedSanType) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der =
      GenerateCsrDer("svc.example.internal", {"svc.example.internal"}, 2048, true);
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Issue(request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::PolicyDenied);
  }
}

TEST(SignerTest, OpenSslSignerRejectsWeakRsaKey) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = GenerateCsrDer("svc.example.internal",
                                   {"svc.example.internal"}, 1024, false);
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Issue(request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::PolicyDenied);
  }
}

TEST(SignerTest, OpenSslSignerClampsTtlToPolicyMaximum) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest request;
  request.csr_der = GenerateCsrDer("svc.example.internal",
                                   {"svc.example.internal"});
  request.subject_common_name = "principal-user";
  request.requested_ttl = std::chrono::hours(48);

  const auto result = signer.Issue(request);
  const auto actual_window = std::chrono::duration_cast<std::chrono::seconds>(
      result.not_after - result.not_before);
  const auto max_window =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(24)) +
      std::chrono::seconds(60);
  EXPECT_LE(actual_window.count(), max_window.count());
}

TEST(SignerTest, OpenSslSignerRenewsCertificateFromExistingLeaf) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  SigningRequest issue_request;
  issue_request.csr_der = GenerateCsrDer("svc.example.internal",
                                         {"svc.example.internal"});
  issue_request.subject_common_name = "principal-user";
  issue_request.requested_ttl = std::chrono::minutes(20);
  const auto issued = signer.Issue(issue_request);

  RenewalSigningRequest renew_request;
  renew_request.certificate_pem = issued.certificate_pem;
  renew_request.requested_ttl = std::chrono::minutes(30);
  const auto renewed = signer.Renew(renew_request);
  EXPECT_FALSE(renewed.certificate_serial.empty());
  EXPECT_FALSE(renewed.certificate_pem.empty());
  EXPECT_NE(renewed.certificate_serial, issued.certificate_serial);
  EXPECT_LT(renewed.not_before, renewed.not_after);
}

TEST(SignerTest, OpenSslSignerRenewRejectsMalformedCertificatePem) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  RenewalSigningRequest renew_request;
  renew_request.certificate_pem = "not-a-certificate";
  renew_request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Renew(renew_request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::InvalidRequest);
  }
}

TEST(SignerTest, OpenSslSignerRenewRejectsCertificateWithoutSan) {
  TempDir temp;
  const auto issuer_pair = GenerateSelfSignedIssuer();
  const auto config = BuildSignerConfig(temp, issuer_pair);
  OpenSslSigner signer(config);

  RenewalSigningRequest renew_request;
  renew_request.certificate_pem = issuer_pair.cert_pem;
  renew_request.requested_ttl = std::chrono::minutes(10);

  try {
    static_cast<void>(signer.Renew(renew_request));
    FAIL() << "expected SignerIssueError";
  } catch (const SignerIssueError& ex) {
    EXPECT_EQ(ex.code(), SignerIssueErrorCode::PolicyDenied);
  }
}

}  // namespace
}  // namespace veritas::notary
