#include "fake_salt.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace veritas::gatekeeper {

FakeSaltGenerator::FakeSaltGenerator(std::string secret)
    : secret_(std::move(secret)) {}

std::string FakeSaltGenerator::Generate(const std::string& login_username) const {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  HMAC(EVP_sha256(),
       reinterpret_cast<const unsigned char*>(secret_.data()),
       static_cast<int>(secret_.size()),
       reinterpret_cast<const unsigned char*>(login_username.data()),
       login_username.size(),
       digest,
       &digest_len);

  return std::string(reinterpret_cast<const char*>(digest), digest_len);
}

}  // namespace veritas::gatekeeper
