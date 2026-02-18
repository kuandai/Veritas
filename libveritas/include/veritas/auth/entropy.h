#pragma once

#include <cstddef>
#include <string>
#include <sys/types.h>

namespace veritas::auth {

enum class EntropyStatus {
  Ready,
  Retryable,
  Failed,
};

struct EntropyCheckResult {
  EntropyStatus status = EntropyStatus::Failed;
  int error_code = 0;
  std::string message;
};

using GetRandomFn = ssize_t (*)(void*, size_t, unsigned int);

EntropyCheckResult CheckEntropyReady();
EntropyCheckResult CheckEntropyReadyWith(GetRandomFn fn);

}  // namespace veritas::auth
