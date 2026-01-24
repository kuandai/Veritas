#include "session_cache.h"

#if !defined(VERITAS_DISABLE_SASL)
#include <sasl/sasl.h>
#endif

namespace veritas::gatekeeper {

SaslConnection::SaslConnection(sasl_conn* conn) : conn_(conn) {}

SaslConnection::~SaslConnection() {
#if !defined(VERITAS_DISABLE_SASL)
  if (conn_) {
    sasl_dispose(&conn_);
  }
#endif
  conn_ = nullptr;
}

SessionCache::SessionCache(std::chrono::seconds ttl) : ttl_(ttl) {}

void SessionCache::Insert(const SrpSession& session) {
  std::lock_guard<std::mutex> lock(mutex_);
  sessions_[session.session_id] = session;
}

std::optional<SrpSession> SessionCache::Get(const std::string& session_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return std::nullopt;
  }
  return it->second;
}

void SessionCache::Erase(const std::string& session_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  sessions_.erase(session_id);
}

void SessionCache::CleanupExpired() {
  const auto now = std::chrono::system_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    if (it->second.expires_at <= now) {
      it = sessions_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace veritas::gatekeeper
