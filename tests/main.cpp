#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char** argv) {
  std::cerr << "veritas_gatekeeper_tests starting\n";
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
