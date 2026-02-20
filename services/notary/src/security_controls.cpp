#include "security_controls.h"

#include <algorithm>
#include <limits>
#include <string>

namespace veritas::notary {

InMemorySecurityMetrics::InMemorySecurityMetrics(size_t max_keys)
    : max_keys_(max_keys) {}

void InMemorySecurityMetrics::Increment(std::string_view counter) {
  if (counter.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = counters_.find(std::string(counter));
  if (it != counters_.end()) {
    ++it->second;
    return;
  }

  if (counters_.size() >= max_keys_) {
    auto min_it = counters_.begin();
    for (auto entry_it = counters_.begin(); entry_it != counters_.end();
         ++entry_it) {
      if (entry_it->second < min_it->second) {
        min_it = entry_it;
      }
    }
    if (min_it != counters_.end()) {
      counters_.erase(min_it);
    }
  }
  counters_.emplace(std::string(counter), 1U);
}

uint64_t InMemorySecurityMetrics::Get(std::string_view counter) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = counters_.find(std::string(counter));
  if (it == counters_.end()) {
    return 0;
  }
  return it->second;
}

FixedWindowRateLimiter::FixedWindowRateLimiter(FixedWindowRateLimiterConfig config)
    : config_(std::move(config)) {}

std::string FixedWindowRateLimiter::SelectEvictionKeyLocked() const {
  std::string selected_key;
  auto oldest_seen = std::chrono::steady_clock::time_point::max();
  for (const auto& [key, entry] : entries_) {
    if (entry.last_seen < oldest_seen) {
      oldest_seen = entry.last_seen;
      selected_key = key;
    }
  }
  return selected_key;
}

bool FixedWindowRateLimiter::Allow(std::string_view key) {
  if (key.empty()) {
    return false;
  }

  const auto now = std::chrono::steady_clock::now();
  const auto cutoff = now - config_.window;
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = entries_.find(std::string(key));
  if (it == entries_.end()) {
    if (entries_.size() >= config_.max_keys) {
      const auto eviction_key = SelectEvictionKeyLocked();
      if (!eviction_key.empty()) {
        entries_.erase(eviction_key);
      }
    }
    it = entries_.emplace(std::string(key), Entry{}).first;
  }

  auto& entry = it->second;
  while (!entry.requests.empty() && entry.requests.front() < cutoff) {
    entry.requests.pop_front();
  }
  entry.last_seen = now;
  if (entry.requests.size() >= config_.max_requests_per_window) {
    return false;
  }
  entry.requests.push_back(now);
  return true;
}

std::string ExtractPeerIdentity(const grpc::ServerContext* context) {
  if (!context) {
    return "unknown";
  }
  const auto peer = context->peer();
  if (peer.empty()) {
    return "unknown";
  }
  if (peer.size() > 256) {
    return peer.substr(0, 256);
  }
  return peer;
}

}  // namespace veritas::notary
