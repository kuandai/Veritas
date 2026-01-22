#include "fake_salt.h"

#include <gtest/gtest.h>

namespace veritas::gatekeeper {

TEST(FakeSaltGeneratorTest, DeterministicForSameInput) {
  FakeSaltGenerator generator("secret");
  const std::string salt_a = generator.Generate("alice");
  const std::string salt_b = generator.Generate("alice");
  EXPECT_EQ(salt_a, salt_b);
}

TEST(FakeSaltGeneratorTest, DifferentForDifferentUsernames) {
  FakeSaltGenerator generator("secret");
  const std::string salt_a = generator.Generate("alice");
  const std::string salt_b = generator.Generate("bob");
  EXPECT_NE(salt_a, salt_b);
}

}  // namespace veritas::gatekeeper
