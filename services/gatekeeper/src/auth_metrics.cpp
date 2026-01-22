#include "auth_metrics.h"

namespace veritas::gatekeeper {

void AuthMetrics::Record(std::string_view ip,
                         std::string_view user_uuid,
                         bool success) {
  std::lock_guard<std::mutex> lock(mutex_);
  RecordLocked(&ip_counters_, ip, success);
  if (!user_uuid.empty()) {
    RecordLocked(&uuid_counters_, user_uuid, success);
  }
}

void AuthMetrics::RecordLocked(std::unordered_map<std::string, AuthCounter>* map,
                               std::string_view key,
                               bool success) {
  if (key.empty()) {
    return;
  }
  auto& counter = (*map)[std::string(key)];
  if (success) {
    ++counter.success;
  } else {
    ++counter.failure;
  }
}

}  // namespace veritas::gatekeeper
