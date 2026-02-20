#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <grpcpp/server_context.h>

namespace veritas::notary {

class SecurityMetrics {
 public:
  virtual ~SecurityMetrics() = default;
  virtual void Increment(std::string_view counter) = 0;
  virtual uint64_t Get(std::string_view counter) const = 0;
};

class InMemorySecurityMetrics final : public SecurityMetrics {
 public:
  explicit InMemorySecurityMetrics(size_t max_keys = 64);

  void Increment(std::string_view counter) override;
  uint64_t Get(std::string_view counter) const override;

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, uint64_t> counters_;
  size_t max_keys_;
};

class RateLimiter {
 public:
  virtual ~RateLimiter() = default;
  virtual bool Allow(std::string_view key) = 0;
};

struct FixedWindowRateLimiterConfig {
  size_t max_requests_per_window = 120;
  size_t max_keys = 10000;
  std::chrono::seconds window = std::chrono::minutes(1);
};

class FixedWindowRateLimiter final : public RateLimiter {
 public:
  explicit FixedWindowRateLimiter(FixedWindowRateLimiterConfig config = {});

  bool Allow(std::string_view key) override;

 private:
  struct Entry {
    std::deque<std::chrono::steady_clock::time_point> requests;
    std::chrono::steady_clock::time_point last_seen{};
  };

  std::string SelectEvictionKeyLocked() const;

  mutable std::mutex mutex_;
  std::unordered_map<std::string, Entry> entries_;
  FixedWindowRateLimiterConfig config_;
};

std::string ExtractPeerIdentity(const grpc::ServerContext* context);

}  // namespace veritas::notary
