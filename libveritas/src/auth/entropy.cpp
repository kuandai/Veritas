#include "veritas/auth/entropy.h"

#include <cerrno>
#include <cstring>
#include <sys/random.h>

namespace veritas::auth {

namespace {

EntropyCheckResult MakeResult(EntropyStatus status, int error_code,
                              const std::string& message) {
  EntropyCheckResult result;
  result.status = status;
  result.error_code = error_code;
  result.message = message;
  return result;
}

}  // namespace

EntropyCheckResult CheckEntropyReady() {
  return CheckEntropyReadyWith(&::getrandom);
}

EntropyCheckResult CheckEntropyReadyWith(GetRandomFn fn) {
  if (!fn) {
    return MakeResult(EntropyStatus::Failed, EINVAL,
                      "entropy source function is required");
  }

  unsigned char sample = 0;
  for (int attempt = 0; attempt < 3; ++attempt) {
    errno = 0;
    const ssize_t read = fn(&sample, sizeof(sample), GRND_NONBLOCK);
    if (read == static_cast<ssize_t>(sizeof(sample))) {
      return MakeResult(EntropyStatus::Ready, 0, "");
    }
    if (read < 0) {
      const int error_code = errno;
      if (error_code == EINTR) {
        continue;
      }
      if (error_code == EAGAIN) {
        return MakeResult(
            EntropyStatus::Retryable, error_code,
            "system entropy is not ready; retry authentication later");
      }
      return MakeResult(EntropyStatus::Failed, error_code,
                        std::string("entropy preflight failed: ") +
                            std::strerror(error_code));
    }
    return MakeResult(EntropyStatus::Failed, EIO,
                      "entropy preflight returned a short read");
  }

  return MakeResult(
      EntropyStatus::Retryable, EINTR,
      "entropy preflight interrupted repeatedly; retry authentication");
}

}  // namespace veritas::auth
