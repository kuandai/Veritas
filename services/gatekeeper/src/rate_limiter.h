#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace veritas::gatekeeper {

class RateLimiter {
 public:
  RateLimiter(int max_events,
              std::chrono::seconds window,
              std::size_t max_keys = 10000);

  bool Allow(const std::string& key);

 private:
  void CleanupLocked(std::deque<std::chrono::system_clock::time_point>* events,
                     std::chrono::system_clock::time_point now);
  void CleanupAllLocked(std::chrono::system_clock::time_point now);
  void EvictOldestBucketLocked();

  int max_events_;
  std::chrono::seconds window_;
  std::size_t max_keys_;
  std::mutex mutex_;
  std::unordered_map<std::string, std::deque<std::chrono::system_clock::time_point>>
      buckets_;
};

}  // namespace veritas::gatekeeper
