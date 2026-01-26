#include "token_utils.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
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

TEST(TokenUtilsTest, GenerateRefreshTokenRejectsZeroLength) {
  EXPECT_THROW(GenerateRefreshToken(0), std::runtime_error);
}

TEST(TokenUtilsTest, HashTokenSha256Deterministic) {
  const std::string first = HashTokenSha256("token");
  const std::string second = HashTokenSha256("token");
  EXPECT_EQ(first, second);
}

}  // namespace veritas::gatekeeper
