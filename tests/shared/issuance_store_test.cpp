#include "veritas/shared/issuance_store.h"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace veritas::shared {
namespace {

IssuanceRecord MakeRecord(std::string serial,
                          std::string token_hash,
                          std::string idempotency_key = "idem") {
  IssuanceRecord record;
  record.certificate_serial = std::move(serial);
  record.certificate_pem = "leaf-cert";
  record.certificate_chain_pem = "intermediate-chain";
  record.user_uuid = "user-1";
  record.token_hash = std::move(token_hash);
  record.idempotency_key = std::move(idempotency_key);
  record.issued_at = std::chrono::system_clock::now();
  record.expires_at = record.issued_at + std::chrono::hours(1);
  return record;
}

TEST(IssuanceStoreTest, InMemoryRoundTripBySerialAndTokenHash) {
  SharedStoreConfig config;
  config.backend = SharedStoreBackend::InMemory;
  const auto store = CreateIssuanceStore(config);

  const auto record = MakeRecord("serial-1", "token-1", "idem-1");
  store->PutIssuance(record);

  const auto by_serial = store->GetBySerial("serial-1");
  ASSERT_TRUE(by_serial.has_value());
  EXPECT_EQ(by_serial->token_hash, "token-1");

  const auto by_token = store->GetByTokenHash("token-1");
  ASSERT_TRUE(by_token.has_value());
  EXPECT_EQ(by_token->certificate_serial, "serial-1");
}

TEST(IssuanceStoreTest, IdempotencyRegistrationRejectsConflicts) {
  SharedStoreConfig config;
  config.backend = SharedStoreBackend::InMemory;
  const auto store = CreateIssuanceStore(config);

  EXPECT_TRUE(store->RegisterIdempotencyKey("idem-key", "serial-1"));
  EXPECT_TRUE(store->RegisterIdempotencyKey("idem-key", "serial-1"));
  EXPECT_FALSE(store->RegisterIdempotencyKey("idem-key", "serial-2"));

  const auto resolved = store->ResolveIdempotencyKey("idem-key");
  ASSERT_TRUE(resolved.has_value());
  EXPECT_EQ(*resolved, "serial-1");
}

TEST(IssuanceStoreTest, RevokeMarksRecordState) {
  SharedStoreConfig config;
  config.backend = SharedStoreBackend::InMemory;
  const auto store = CreateIssuanceStore(config);

  store->PutIssuance(MakeRecord("serial-1", "token-1", "idem-1"));
  const auto now = std::chrono::system_clock::now();
  store->Revoke("serial-1", "policy_violation", now);

  const auto updated = store->GetBySerial("serial-1");
  ASSERT_TRUE(updated.has_value());
  EXPECT_EQ(updated->state, IssuanceState::Revoked);
  EXPECT_EQ(updated->revoke_reason, "policy_violation");
}

TEST(IssuanceStoreTest, IdempotencyRegistrationIsThreadSafe) {
  SharedStoreConfig config;
  config.backend = SharedStoreBackend::InMemory;
  const auto store = CreateIssuanceStore(config);

  constexpr int kThreads = 16;
  std::atomic<int> success_count{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int i = 0; i < kThreads; ++i) {
    workers.emplace_back([&, i] {
      const bool success =
          store->RegisterIdempotencyKey("idem-concurrent",
                                        "serial-" + std::to_string(i));
      if (success) {
        success_count.fetch_add(1);
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }

  EXPECT_EQ(success_count.load(), 1);
  const auto resolved = store->ResolveIdempotencyKey("idem-concurrent");
  ASSERT_TRUE(resolved.has_value());
}

TEST(IssuanceStoreTest, RedisBackendRequiresUri) {
  SharedStoreConfig config;
  config.backend = SharedStoreBackend::Redis;
  config.redis_uri.clear();
  EXPECT_THROW(static_cast<void>(CreateIssuanceStore(config)), SharedStoreError);
}

}  // namespace
}  // namespace veritas::shared
