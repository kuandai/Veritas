#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace veritas::gatekeeper {

struct AuthCounter {
  uint64_t success = 0;
  uint64_t failure = 0;
  std::chrono::steady_clock::time_point last_seen{};
};

class AuthMetrics {
 public:
  explicit AuthMetrics(std::size_t max_ip_keys = 10000,
                       std::size_t max_uuid_keys = 10000);

  void Record(std::string_view ip, std::string_view user_uuid, bool success);
  std::size_t IpKeyCount() const;
  std::size_t UuidKeyCount() const;
  std::optional<AuthCounter> GetIpCounter(std::string_view ip) const;
  std::optional<AuthCounter> GetUuidCounter(std::string_view user_uuid) const;

 private:
  void RecordLocked(std::unordered_map<std::string, AuthCounter>* map,
                    std::string_view key,
                    bool success,
                    std::size_t max_keys,
                    std::chrono::steady_clock::time_point now);
  static void EvictOldestLocked(std::unordered_map<std::string, AuthCounter>* map);

  mutable std::mutex mutex_;
  std::unordered_map<std::string, AuthCounter> ip_counters_;
  std::unordered_map<std::string, AuthCounter> uuid_counters_;
  std::size_t max_ip_keys_;
  std::size_t max_uuid_keys_;
};

}  // namespace veritas::gatekeeper
