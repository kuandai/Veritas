#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace veritas::gatekeeper {

class RateLimiter {
 public:
  RateLimiter(int max_events, std::chrono::seconds window);

  bool Allow(const std::string& key);

 private:
  void CleanupLocked(const std::string& key,
                     std::deque<std::chrono::system_clock::time_point>* events,
                     std::chrono::system_clock::time_point now);

  int max_events_;
  std::chrono::seconds window_;
  std::mutex mutex_;
  std::unordered_map<std::string, std::deque<std::chrono::system_clock::time_point>>
      buckets_;
};

}  // namespace veritas::gatekeeper
