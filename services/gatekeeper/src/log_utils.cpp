#include "log_utils.h"

#include <iomanip>
#include <sstream>

namespace veritas::gatekeeper {

std::string JsonEscape(std::string_view value) {
  std::ostringstream stream;
  stream << std::hex << std::uppercase;
  for (const unsigned char ch : value) {
    switch (ch) {
      case '\"':
        stream << "\\\"";
        break;
      case '\\':
        stream << "\\\\";
        break;
      case '\b':
        stream << "\\b";
        break;
      case '\f':
        stream << "\\f";
        break;
      case '\n':
        stream << "\\n";
        break;
      case '\r':
        stream << "\\r";
        break;
      case '\t':
        stream << "\\t";
        break;
      default:
        if (ch < 0x20) {
          stream << "\\u" << std::setw(4) << std::setfill('0')
                 << static_cast<int>(ch);
          stream << std::setfill(' ');
        } else {
          stream << static_cast<char>(ch);
        }
        break;
    }
  }
  return stream.str();
}

}  // namespace veritas::gatekeeper
