#include "veritas/auth/entropy.h"
#include "veritas/identity_manager.h"

#include <cerrno>
#include <cstring>

#include <gtest/gtest.h>

namespace veritas::auth {
namespace {

ssize_t AlwaysReady(void* buf, size_t len, unsigned int /*flags*/) {
  if (len > 0 && buf) {
    std::memset(buf, 0xAC, len);
  }
  return static_cast<ssize_t>(len);
}

ssize_t RetryableEagain(void* /*buf*/, size_t /*len*/, unsigned int /*flags*/) {
  errno = EAGAIN;
  return -1;
}

ssize_t HardFailure(void* /*buf*/, size_t /*len*/, unsigned int /*flags*/) {
  errno = EIO;
  return -1;
}

ssize_t InterruptedThenReady(void* buf, size_t len, unsigned int /*flags*/) {
  static int calls = 0;
  ++calls;
  if (calls < 3) {
    errno = EINTR;
    return -1;
  }
  if (len > 0 && buf) {
    std::memset(buf, 0xBC, len);
  }
  return static_cast<ssize_t>(len);
}

}  // namespace

TEST(EntropyTest, ReportsReadyWhenGetrandomSucceeds) {
  const EntropyCheckResult result = CheckEntropyReadyWith(&AlwaysReady);
  EXPECT_EQ(result.status, EntropyStatus::Ready);
  EXPECT_EQ(result.error_code, 0);
}

TEST(EntropyTest, MapsEagainToRetryableStatus) {
  const EntropyCheckResult result = CheckEntropyReadyWith(&RetryableEagain);
  EXPECT_EQ(result.status, EntropyStatus::Retryable);
  EXPECT_EQ(result.error_code, EAGAIN);
}

TEST(EntropyTest, MapsUnexpectedFailureToFailedStatus) {
  const EntropyCheckResult result = CheckEntropyReadyWith(&HardFailure);
  EXPECT_EQ(result.status, EntropyStatus::Failed);
  EXPECT_EQ(result.error_code, EIO);
}

TEST(EntropyTest, RetriesInterruptedCalls) {
  const EntropyCheckResult result = CheckEntropyReadyWith(&InterruptedThenReady);
  EXPECT_EQ(result.status, EntropyStatus::Ready);
  EXPECT_EQ(result.error_code, 0);
}

TEST(EntropyTest, IdentityManagerFailsFastOnEntropyRetryableStatus) {
  veritas::IdentityManager manager(
      [] { return std::string("unused"); }, std::nullopt, [] {
        EntropyCheckResult result;
        result.status = EntropyStatus::Retryable;
        result.error_code = EAGAIN;
        result.message = "entropy not ready";
        return result;
      });

  veritas::GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;

  try {
    static_cast<void>(manager.Authenticate(config, "user", "pass"));
    FAIL() << "Authenticate should fail on entropy preflight";
  } catch (const veritas::IdentityManagerError& ex) {
    EXPECT_EQ(ex.code(), veritas::IdentityErrorCode::EntropyUnavailable);
  }
  EXPECT_EQ(manager.GetLastError(),
            veritas::IdentityErrorCode::EntropyUnavailable);
}

}  // namespace veritas::auth
