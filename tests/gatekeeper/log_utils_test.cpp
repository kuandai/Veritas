#include "log_utils.h"

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(LogUtilsTest, EscapesQuotesAndBackslashes) {
  const std::string escaped = JsonEscape("x\"y\\z");
  EXPECT_EQ(escaped, "x\\\"y\\\\z");
}

TEST(LogUtilsTest, EscapesControlCharacters) {
  const std::string escaped = JsonEscape("line1\nline2\r\t");
  EXPECT_EQ(escaped, "line1\\nline2\\r\\t");
}

TEST(LogUtilsTest, EscapesLowAsciiAsUnicode) {
  std::string value;
  value.push_back('\x01');
  value.push_back('\x1f');
  const std::string escaped = JsonEscape(value);
  EXPECT_EQ(escaped, "\\u0001\\u001F");
}

}  // namespace veritas::gatekeeper
