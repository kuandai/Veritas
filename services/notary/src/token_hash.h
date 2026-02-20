#pragma once

#include <string>
#include <string_view>

namespace veritas::notary {

std::string HashTokenSha256(std::string_view token);

}  // namespace veritas::notary
