#include "token_utils.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>
#include <openssl/sha.h>

namespace veritas::gatekeeper {

std::string HexEncodeBytes(std::string_view bytes) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (unsigned char byte : bytes) {
    stream << std::setw(2) << static_cast<int>(byte);
  }
  return stream.str();
}

std::string GenerateRefreshToken(std::size_t num_bytes) {
  if (num_bytes == 0) {
    throw std::runtime_error("Refresh token length must be non-zero");
  }

  std::vector<unsigned char> buffer(num_bytes);
  if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed to generate refresh token");
  }

  return std::string(reinterpret_cast<const char*>(buffer.data()), buffer.size());
}

std::string HashTokenSha256(const std::string& token) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(token.data()), token.size(), digest);
  return HexEncodeBytes(std::string_view(reinterpret_cast<const char*>(digest),
                                         sizeof(digest)));
}

}  // namespace veritas::gatekeeper
