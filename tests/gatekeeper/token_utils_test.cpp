#include "token_utils.h"

#include <algorithm>
#include <cctype>
#include <string>

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(TokenUtilsTest, HashTokenSha256ReturnsHex) {
  const std::string hash = HashTokenSha256("test-token");
  EXPECT_EQ(hash.size(), 64u);
  const bool all_hex = std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0;
  });
  EXPECT_TRUE(all_hex);
}

TEST(TokenUtilsTest, GenerateRefreshTokenLength) {
  const std::string token = GenerateRefreshToken(32);
  EXPECT_EQ(token.size(), 32u);
}

}  // namespace veritas::gatekeeper
