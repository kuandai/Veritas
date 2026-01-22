#include "token_store.h"

namespace veritas::gatekeeper {

void InMemoryTokenStore::PutToken(const TokenRecord& record) {
  std::lock_guard<std::mutex> lock(mutex_);
  tokens_[record.token_hash] = record;
}

std::optional<TokenRecord> InMemoryTokenStore::GetToken(
    const std::string& token_hash) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = tokens_.find(token_hash);
  if (it == tokens_.end()) {
    return std::nullopt;
  }
  return it->second;
}

void InMemoryTokenStore::RevokeUser(const std::string& user_uuid) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : tokens_) {
    if (entry.second.user_uuid == user_uuid) {
      entry.second.is_revoked = true;
    }
  }
}

}  // namespace veritas::gatekeeper
