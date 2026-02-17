#include "auth_metrics.h"

#include <iterator>
#include <utility>

namespace veritas::gatekeeper {

AuthMetrics::AuthMetrics(std::size_t max_ip_keys, std::size_t max_uuid_keys)
    : max_ip_keys_(max_ip_keys), max_uuid_keys_(max_uuid_keys) {}

void AuthMetrics::Record(std::string_view ip,
                         std::string_view user_uuid,
                         bool success) {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  RecordLocked(&ip_counters_, ip, success, max_ip_keys_, now);
  if (!user_uuid.empty()) {
    RecordLocked(&uuid_counters_, user_uuid, success, max_uuid_keys_, now);
  }
}

std::size_t AuthMetrics::IpKeyCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ip_counters_.size();
}

std::size_t AuthMetrics::UuidKeyCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return uuid_counters_.size();
}

std::optional<AuthCounter> AuthMetrics::GetIpCounter(std::string_view ip) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = ip_counters_.find(std::string(ip));
  if (it == ip_counters_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<AuthCounter> AuthMetrics::GetUuidCounter(
    std::string_view user_uuid) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = uuid_counters_.find(std::string(user_uuid));
  if (it == uuid_counters_.end()) {
    return std::nullopt;
  }
  return it->second;
}

void AuthMetrics::RecordLocked(std::unordered_map<std::string, AuthCounter>* map,
                               std::string_view key,
                               bool success,
                               std::size_t max_keys,
                               std::chrono::steady_clock::time_point now) {
  if (key.empty()) {
    return;
  }

  std::string key_copy(key);
  auto it = map->find(key_copy);
  if (it == map->end()) {
    if (max_keys == 0) {
      return;
    }
    if (map->size() >= max_keys) {
      EvictOldestLocked(map);
    }
    auto [insert_it, inserted] =
        map->emplace(std::move(key_copy), AuthCounter{});
    (void)inserted;
    it = insert_it;
  }

  auto& counter = it->second;
  if (success) {
    ++counter.success;
  } else {
    ++counter.failure;
  }
  counter.last_seen = now;
}

void AuthMetrics::EvictOldestLocked(
    std::unordered_map<std::string, AuthCounter>* map) {
  if (map->empty()) {
    return;
  }

  auto victim = map->begin();
  auto victim_seen = victim->second.last_seen;
  for (auto it = std::next(map->begin()); it != map->end(); ++it) {
    if (it->second.last_seen < victim_seen) {
      victim = it;
      victim_seen = it->second.last_seen;
    }
  }
  map->erase(victim);
}

}  // namespace veritas::gatekeeper
