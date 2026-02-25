#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

struct sasl_conn;

namespace veritas::gatekeeper {

class SaslConnection {
 public:
  explicit SaslConnection(sasl_conn* conn);
  ~SaslConnection();

  SaslConnection(const SaslConnection&) = delete;
  SaslConnection& operator=(const SaslConnection&) = delete;

  sasl_conn* get() const { return conn_; }

 private:
  sasl_conn* conn_ = nullptr;
};

struct SrpSession {
  std::string session_id;
  std::string login_username;
  std::chrono::system_clock::time_point expires_at;
  std::shared_ptr<SaslConnection> sasl_conn;
  bool is_fake = false;
};

struct CompletedSrpSession {
  std::string session_id;
  std::string client_proof_hash;
  std::string server_proof;
  std::string user_uuid;
  std::string refresh_token;
  std::chrono::system_clock::time_point token_expires_at;
  std::chrono::system_clock::time_point expires_at;
};

class SessionCache {
 public:
  explicit SessionCache(std::chrono::seconds ttl);

  void Insert(const SrpSession& session);
  std::optional<SrpSession> Get(const std::string& session_id);
  std::optional<SrpSession> Take(const std::string& session_id);
  void InsertCompleted(const CompletedSrpSession& session);
  std::optional<CompletedSrpSession> GetCompleted(
      const std::string& session_id);
  void Erase(const std::string& session_id);
  void CleanupExpired();

 private:
  std::chrono::seconds ttl_;
  std::unordered_map<std::string, SrpSession> sessions_;
  std::unordered_map<std::string, CompletedSrpSession> completed_sessions_;
  std::mutex mutex_;
};

}  // namespace veritas::gatekeeper
