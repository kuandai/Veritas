#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace veritas::gatekeeper {

std::string HexEncodeBytes(std::string_view bytes);
std::string GenerateRefreshToken(std::size_t num_bytes = 32);
std::string HashTokenSha256(const std::string& token);

}  // namespace veritas::gatekeeper
