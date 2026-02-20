#include "log_utils.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace veritas::notary {
namespace {

std::string JsonEscape(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (char ch : input) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out += ch;
        break;
    }
  }
  return out;
}

std::string UtcTimestampNow() {
  const auto now = std::chrono::system_clock::now();
  const auto tt = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return os.str();
}

}  // namespace

void LogNotaryEvent(std::string_view action,
                    const grpc::Status& status,
                    std::string_view detail) {
  std::cout << "{\"timestamp\":\"" << UtcTimestampNow()
            << "\",\"component\":\"notary\""
            << ",\"action\":\"" << JsonEscape(action) << "\""
            << ",\"status\":\"" << status.error_code() << "\"";
  if (!detail.empty()) {
    std::cout << ",\"detail\":\"" << JsonEscape(detail) << "\"";
  }
  if (!status.ok()) {
    std::cout << ",\"error\":\"" << JsonEscape(status.error_message()) << "\"";
  }
  std::cout << "}\n";
}

}  // namespace veritas::notary
