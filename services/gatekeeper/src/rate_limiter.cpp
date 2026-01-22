#include "rate_limiter.h"

namespace veritas::gatekeeper {

RateLimiter::RateLimiter(int max_events, std::chrono::seconds window)
    : max_events_(max_events), window_(window) {}

bool RateLimiter::Allow(const std::string& key) {
  if (max_events_ <= 0) {
    return true;
  }

  const auto now = std::chrono::system_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  auto& events = buckets_[key];
  CleanupLocked(key, &events, now);
  if (static_cast<int>(events.size()) >= max_events_) {
    return false;
  }
  events.push_back(now);
  return true;
}

void RateLimiter::CleanupLocked(
    const std::string& key,
    std::deque<std::chrono::system_clock::time_point>* events,
    std::chrono::system_clock::time_point now) {
  const auto cutoff = now - window_;
  while (!events->empty() && events->front() <= cutoff) {
    events->pop_front();
  }
  if (events->empty()) {
    buckets_.erase(key);
  }
}

}  // namespace veritas::gatekeeper
