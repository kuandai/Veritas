#include "token_hash.h"

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <openssl/sha.h>

namespace veritas::notary {

std::string HashTokenSha256(std::string_view token) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
  SHA256(reinterpret_cast<const unsigned char*>(token.data()), token.size(),
         digest.data());

  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto value : digest) {
    out << std::setw(2) << static_cast<unsigned int>(value);
  }
  const auto result = out.str();
  if (result.size() != SHA256_DIGEST_LENGTH * 2U) {
    throw std::runtime_error("failed to hash token");
  }
  return result;
}

}  // namespace veritas::notary
