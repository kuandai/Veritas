#include "auth/secure_buffer.h"

#include <gtest/gtest.h>

namespace veritas::auth {

TEST(SecureStringTest, ScrubZeroesBuffer) {
  SecureString secret("short-secret");
  std::string_view view = secret.view();
  auto* data = const_cast<char*>(view.data());
  const std::size_t size = view.size();

  secret.Scrub();

  bool all_zero = true;
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] != '\0') {
      all_zero = false;
      break;
    }
  }
  EXPECT_TRUE(all_zero);
}

}  // namespace veritas::auth
