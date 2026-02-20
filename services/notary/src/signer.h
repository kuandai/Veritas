#pragma once

#include <chrono>
#include <stdexcept>
#include <string>

namespace veritas::notary {

struct SignerConfig {
  std::string issuer_cert_path;
  std::string issuer_key_path;
  std::string issuer_chain_path;
};

enum class SignerConfigErrorCode {
  MissingIssuerCertificatePath,
  MissingIssuerPrivateKeyPath,
  UnreadableIssuerCertificate,
  UnreadableIssuerPrivateKey,
  InvalidIssuerCertificate,
  InvalidIssuerPrivateKey,
  KeyCertificateMismatch,
};

class SignerConfigError : public std::runtime_error {
 public:
  SignerConfigError(SignerConfigErrorCode code, const std::string& message);

  SignerConfigErrorCode code() const noexcept;

 private:
  SignerConfigErrorCode code_;
};

enum class SignerIssueErrorCode {
  InvalidRequest,
  PolicyDenied,
  Internal,
};

class SignerIssueError : public std::runtime_error {
 public:
  SignerIssueError(SignerIssueErrorCode code, const std::string& message);

  SignerIssueErrorCode code() const noexcept;

 private:
  SignerIssueErrorCode code_;
};

struct SigningRequest {
  std::string csr_der;
  std::chrono::seconds requested_ttl{};
};

struct SigningResult {
  std::string certificate_pem;
  std::string certificate_chain_pem;
  std::string certificate_serial;
  std::chrono::system_clock::time_point not_before{};
  std::chrono::system_clock::time_point not_after{};
};

class Signer {
 public:
  virtual ~Signer() = default;

  virtual SigningResult Issue(const SigningRequest& request) = 0;
};

void ValidateSignerKeyMaterial(const SignerConfig& config);

class OpenSslSigner final : public Signer {
 public:
  explicit OpenSslSigner(SignerConfig config);

  const SignerConfig& config() const noexcept;

  SigningResult Issue(const SigningRequest& request) override;

 private:
  SignerConfig config_;
};

}  // namespace veritas::notary
