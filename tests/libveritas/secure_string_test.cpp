#include "auth/secure_buffer.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>

#include <gtest/gtest.h>

namespace veritas::auth {
namespace {

struct SecureBufferTestHooks {
  static void Reset() {
    allocated = nullptr;
    allocated_size = 0;
    memzero_calls = 0;
  }

  static void* Alloc(std::size_t size) {
    allocated = static_cast<unsigned char*>(std::malloc(size));
    allocated_size = size;
    return allocated;
  }

  static void* FailAlloc(std::size_t /*size*/) { return nullptr; }

  static void FreeNoop(void* /*ptr*/) {}

  static int LockOk(void* /*ptr*/, std::size_t /*size*/) { return 0; }

  static int LockFail(void* /*ptr*/, std::size_t /*size*/) {
    errno = ENOSYS;
    return -1;
  }

  static int UnlockOk(void* /*ptr*/, std::size_t /*size*/) { return 0; }

  static void Memzero(void* ptr, std::size_t size) {
    ++memzero_calls;
    std::memset(ptr, 0, size);
  }

  static inline unsigned char* allocated = nullptr;
  static inline std::size_t allocated_size = 0;
  static inline int memzero_calls = 0;
};

}  // namespace

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

TEST(SecureStringTest, DestructionWipesMemoryWhenLockFails) {
  SecureBufferTestHooks::Reset();
  {
    SecureBuffer secret(
        "secret-123", {&SecureBufferTestHooks::Alloc,
                       &SecureBufferTestHooks::FreeNoop,
                       &SecureBufferTestHooks::LockFail,
                       &SecureBufferTestHooks::UnlockOk,
                       &SecureBufferTestHooks::Memzero});
    EXPECT_TRUE(secret.lock_attempted());
    EXPECT_FALSE(secret.is_locked());
  }

  ASSERT_NE(SecureBufferTestHooks::allocated, nullptr);
  ASSERT_GT(SecureBufferTestHooks::allocated_size, 0u);
  EXPECT_GT(SecureBufferTestHooks::memzero_calls, 0);
  for (std::size_t i = 0; i < SecureBufferTestHooks::allocated_size; ++i) {
    EXPECT_EQ(SecureBufferTestHooks::allocated[i], 0);
  }
  std::free(SecureBufferTestHooks::allocated);
  SecureBufferTestHooks::Reset();
}

TEST(SecureStringTest, ReportsLockSuccessWhenMlockWorks) {
  SecureBufferTestHooks::Reset();
  {
    SecureBuffer secret(
        "secret-456", {&SecureBufferTestHooks::Alloc,
                       &SecureBufferTestHooks::FreeNoop,
                       &SecureBufferTestHooks::LockOk,
                       &SecureBufferTestHooks::UnlockOk,
                       &SecureBufferTestHooks::Memzero});
    EXPECT_TRUE(secret.lock_attempted());
    EXPECT_TRUE(secret.is_locked());
  }
  if (SecureBufferTestHooks::allocated) {
    std::free(SecureBufferTestHooks::allocated);
  }
  SecureBufferTestHooks::Reset();
}

TEST(SecureStringTest, FailsWhenSecureAllocationFails) {
  EXPECT_THROW(
      (void)SecureBuffer("nope", {&SecureBufferTestHooks::FailAlloc,
                                  &SecureBufferTestHooks::FreeNoop,
                                  &SecureBufferTestHooks::LockOk,
                                  &SecureBufferTestHooks::UnlockOk,
                                  &SecureBufferTestHooks::Memzero}),
      std::bad_alloc);
}

}  // namespace veritas::auth
