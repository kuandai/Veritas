#pragma once

#include <cstddef>
#include <string>

namespace veritas::gatekeeper {

std::string GenerateRefreshToken(std::size_t num_bytes = 32);
std::string HashTokenSha256(const std::string& token);

}  // namespace veritas::gatekeeper
