#include "veritas/shared/issuance_store.h"
#include "veritas/shared/token_store.h"

#include <chrono>

#include <gtest/gtest.h>

namespace veritas::shared {
namespace {

TokenRecord MakeToken(std::string hash, std::string user_uuid) {
  TokenRecord record;
  record.token_hash = std::move(hash);
  record.user_uuid = std::move(user_uuid);
  record.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
  return record;
}

IssuanceRecord MakeIssuance(std::string serial, std::string token_hash) {
  IssuanceRecord record;
  record.certificate_serial = std::move(serial);
  record.certificate_pem = "leaf-cert";
  record.certificate_chain_pem = "intermediate-chain";
  record.user_uuid = "user-1";
  record.token_hash = std::move(token_hash);
  record.idempotency_key = "idem-1";
  record.issued_at = std::chrono::system_clock::now();
  record.expires_at = record.issued_at + std::chrono::hours(1);
  return record;
}

TEST(TokenStoreTest, InMemoryRevocationCreatesTombstoneAndRejectsReplay) {
  InMemoryTokenStore store;
  const auto record = MakeToken("hash-1", "user-1");
  store.PutToken(record);

  store.RevokeToken("hash-1", "TOKEN_REVOKED");

  const auto status = store.GetTokenStatus("hash-1");
  EXPECT_EQ(status.state, TokenState::Revoked);
  EXPECT_EQ(status.reason, "TOKEN_REVOKED");

  EXPECT_THROW(store.PutToken(record), TokenStoreError);
}

TEST(TokenStoreTest, RevokeUserMarksAllUserTokensAsRevoked) {
  InMemoryTokenStore store;
  store.PutToken(MakeToken("hash-1", "user-1"));
  store.PutToken(MakeToken("hash-2", "user-1"));
  store.PutToken(MakeToken("hash-3", "user-2"));

  store.RevokeUser("user-1");

  EXPECT_EQ(store.GetTokenStatus("hash-1").state, TokenState::Revoked);
  EXPECT_EQ(store.GetTokenStatus("hash-2").state, TokenState::Revoked);
  EXPECT_EQ(store.GetTokenStatus("hash-3").state, TokenState::Active);
}

TEST(TokenStoreTest,
     RevokedTokenRemainsLinkedToIssuanceForCrossServiceLifecycleChecks) {
  SharedStoreConfig store_config;
  store_config.backend = SharedStoreBackend::InMemory;
  const auto issuance_store = CreateIssuanceStore(store_config);

  InMemoryTokenStore token_store;
  token_store.PutToken(MakeToken("token-hash-1", "user-1"));
  issuance_store->PutIssuance(MakeIssuance("serial-1", "token-hash-1"));

  token_store.RevokeToken("token-hash-1", "TOKEN_REVOKED");

  const auto status = token_store.GetTokenStatus("token-hash-1");
  ASSERT_EQ(status.state, TokenState::Revoked);
  EXPECT_EQ(status.reason, "TOKEN_REVOKED");

  const auto issuance = issuance_store->GetByTokenHash("token-hash-1");
  ASSERT_TRUE(issuance.has_value());
  EXPECT_EQ(issuance->certificate_serial, "serial-1");
  EXPECT_EQ(issuance->state, IssuanceState::Active);
}

}  // namespace
}  // namespace veritas::shared
