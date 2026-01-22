#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace veritas::gatekeeper {

struct AuthCounter {
  uint64_t success = 0;
  uint64_t failure = 0;
};

class AuthMetrics {
 public:
  void Record(std::string_view ip, std::string_view user_uuid, bool success);

 private:
  void RecordLocked(std::unordered_map<std::string, AuthCounter>* map,
                    std::string_view key,
                    bool success);

  std::mutex mutex_;
  std::unordered_map<std::string, AuthCounter> ip_counters_;
  std::unordered_map<std::string, AuthCounter> uuid_counters_;
};

}  // namespace veritas::gatekeeper
