#include "auth/gatekeeper_client.h"

#include <gtest/gtest.h>

namespace veritas::auth {
namespace {

TEST(GatekeeperClientTest, InsecureTransportPolicyMatchesBuildType) {
  GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;

#if defined(NDEBUG)
  EXPECT_THROW(GatekeeperClient client(config), std::runtime_error);
#else
  EXPECT_NO_THROW(GatekeeperClient client(config));
#endif
}

}  // namespace
}  // namespace veritas::auth
