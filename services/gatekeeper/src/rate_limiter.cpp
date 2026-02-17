#include "rate_limiter.h"

#include <iterator>

namespace veritas::gatekeeper {

RateLimiter::RateLimiter(int max_events,
                         std::chrono::seconds window,
                         std::size_t max_keys)
    : max_events_(max_events), window_(window), max_keys_(max_keys) {}

bool RateLimiter::Allow(const std::string& key) {
  if (max_events_ <= 0) {
    return true;
  }

  const auto now = std::chrono::system_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  CleanupAllLocked(now);

  auto it = buckets_.find(key);
  if (it == buckets_.end()) {
    if (max_keys_ == 0) {
      return false;
    }
    if (buckets_.size() >= max_keys_) {
      EvictOldestBucketLocked();
    }
    it = buckets_.emplace(key,
                          std::deque<std::chrono::system_clock::time_point>{})
             .first;
  }

  auto& events = it->second;
  CleanupLocked(&events, now);
  if (static_cast<int>(events.size()) >= max_events_) {
    return false;
  }
  events.push_back(now);
  return true;
}

void RateLimiter::CleanupLocked(
    std::deque<std::chrono::system_clock::time_point>* events,
    std::chrono::system_clock::time_point now) {
  const auto cutoff = now - window_;
  while (!events->empty() && events->front() <= cutoff) {
    events->pop_front();
  }
}

void RateLimiter::CleanupAllLocked(std::chrono::system_clock::time_point now) {
  for (auto it = buckets_.begin(); it != buckets_.end();) {
    CleanupLocked(&it->second, now);
    if (it->second.empty()) {
      it = buckets_.erase(it);
    } else {
      ++it;
    }
  }
}

void RateLimiter::EvictOldestBucketLocked() {
  if (buckets_.empty()) {
    return;
  }

  auto victim = buckets_.begin();
  auto victim_last = victim->second.back();
  for (auto it = std::next(buckets_.begin()); it != buckets_.end(); ++it) {
    const auto last = it->second.back();
    if (last < victim_last) {
      victim = it;
      victim_last = last;
    }
  }
  buckets_.erase(victim);
}

}  // namespace veritas::gatekeeper
