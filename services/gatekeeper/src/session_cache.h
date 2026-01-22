#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace veritas::gatekeeper {

struct SrpSession {
  std::string session_id;
  std::string login_username;
  std::chrono::system_clock::time_point expires_at;
};

class SessionCache {
 public:
  explicit SessionCache(std::chrono::seconds ttl);

  void Insert(const SrpSession& session);
  std::optional<SrpSession> Get(const std::string& session_id);
  void Erase(const std::string& session_id);
  void CleanupExpired();

 private:
  std::chrono::seconds ttl_;
  std::unordered_map<std::string, SrpSession> sessions_;
  std::mutex mutex_;
};

}  // namespace veritas::gatekeeper
