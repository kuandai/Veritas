#pragma once

#include <string>
#include <string_view>

namespace veritas::gatekeeper {

std::string JsonEscape(std::string_view value);

}  // namespace veritas::gatekeeper
