#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sasl/sasl.h>

namespace veritas::auth {

class SaslClient {
 public:
  SaslClient(std::string service,
             std::string username,
             std::string_view password);
  ~SaslClient();

  SaslClient(const SaslClient&) = delete;
  SaslClient& operator=(const SaslClient&) = delete;

  std::string ComputeClientProof(std::string_view server_public);
  void VerifyServerProof(std::string_view server_proof);

 private:
  struct SecretBuffer {
    explicit SecretBuffer(std::string_view password);
    ~SecretBuffer();

    sasl_secret_t* get();

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&&) noexcept = default;
    SecretBuffer& operator=(SecretBuffer&&) noexcept = default;

   private:
    std::vector<unsigned char> buffer_;
  };

  struct CallbackContext {
    std::string username;
    SecretBuffer secret;
  };

  static void EnsureInitialized();

  static int GetSimple(void* context, int id, const char** result, unsigned* len);
  static int GetSecret(sasl_conn_t* conn, void* context, int id,
                       sasl_secret_t** psecret);

  void Start();

  std::string service_;
  sasl_conn_t* conn_ = nullptr;
  std::unique_ptr<CallbackContext> context_;
  std::vector<sasl_callback_t> callbacks_;
  bool started_ = false;
};

}  // namespace veritas::auth
