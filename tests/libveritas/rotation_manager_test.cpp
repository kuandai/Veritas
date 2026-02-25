#include "veritas/identity_manager.h"
#include "veritas/storage/token_store.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace veritas {
namespace {

struct BioDeleter {
  void operator()(BIO* bio) const { BIO_free(bio); }
};

struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

struct PkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};

struct KeyCertPair {
  std::string key_pem;
  std::string cert_pem;
};

std::filesystem::path UniqueTempFile(const std::string& suffix) {
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() /
         ("veritas_rotation_test_" + std::to_string(now) + "_" + suffix);
}

std::string BioToString(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (!mem || !mem->data || mem->length == 0) {
    return {};
  }
  return std::string(mem->data, mem->length);
}

std::unique_ptr<EVP_PKEY, PkeyDeleter> GenerateKey() {
  std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx) {
    throw std::runtime_error("failed to allocate keygen context");
  }
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("failed to init keygen");
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) {
    throw std::runtime_error("failed to set RSA bits");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
    throw std::runtime_error("failed to generate key");
  }
  return std::unique_ptr<EVP_PKEY, PkeyDeleter>(pkey);
}

KeyCertPair GenerateSelfSigned() {
  auto key = GenerateKey();
  std::unique_ptr<X509, X509Deleter> cert(X509_new());
  if (!cert) {
    throw std::runtime_error("failed to allocate cert");
  }
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), -60);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 60 * 60);
  X509_set_pubkey(cert.get(), key.get());

  X509_NAME* name = X509_get_subject_name(cert.get());
  const unsigned char cn[] = "veritas-rotation-test";
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
    throw std::runtime_error("failed to sign cert");
  }

  std::unique_ptr<BIO, BioDeleter> key_bio(BIO_new(BIO_s_mem()));
  std::unique_ptr<BIO, BioDeleter> cert_bio(BIO_new(BIO_s_mem()));
  if (!key_bio || !cert_bio) {
    throw std::runtime_error("failed to allocate PEM BIO");
  }
  if (PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0,
                                nullptr, nullptr) != 1) {
    throw std::runtime_error("failed to write key PEM");
  }
  if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
    throw std::runtime_error("failed to write cert PEM");
  }

  KeyCertPair out;
  out.key_pem = BioToString(key_bio.get());
  out.cert_pem = BioToString(cert_bio.get());
  return out;
}

auth::EntropyCheckResult ReadyEntropy() {
  auth::EntropyCheckResult result;
  result.status = auth::EntropyStatus::Ready;
  return result;
}

TEST(RotationPolicyTest, ComputesSeventyThirtyDeadline) {
  AuthResult identity;
  identity.issued_at = std::chrono::system_clock::time_point(std::chrono::seconds(1000));
  identity.expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(2000));

  const auto deadline = IdentityManager::ComputeRotationDeadline(
      identity, 0.70, identity.issued_at);
  EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(
                deadline.time_since_epoch())
                .count(),
            1700);
}

TEST(RotationPolicyTest, BackoffDelayRespectsJitterAndMax) {
  const auto low = IdentityManager::ComputeBackoffDelay(
      1, std::chrono::milliseconds(100), std::chrono::milliseconds(1000), 0.20,
      0.0);
  const auto high = IdentityManager::ComputeBackoffDelay(
      1, std::chrono::milliseconds(100), std::chrono::milliseconds(1000), 0.20,
      1.0);
  const auto capped = IdentityManager::ComputeBackoffDelay(
      12, std::chrono::milliseconds(100), std::chrono::milliseconds(1000), 0.50,
      1.0);

  EXPECT_EQ(low.count(), 80);
  EXPECT_EQ(high.count(), 120);
  EXPECT_LE(capped.count(), 1000);
  EXPECT_GE(capped.count(), 1);
}

TEST(RotationWorkerTest, EmitsUnreachableWarning) {
  storage::TokenStoreConfig store_config;
  store_config.backend = storage::TokenStoreBackend::File;
  store_config.allow_insecure_fallback = true;
  store_config.file_path = UniqueTempFile("unreachable").string();
  store_config.machine_identity_override = "test-machine";

  auto store = storage::CreateTokenStore(store_config);
  storage::StoredIdentity seeded;
  seeded.user_uuid = "seed-user";
  seeded.refresh_token = "seed-refresh";
  seeded.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(10);
  store->Save(seeded);

  IdentityManager manager(
      [] { return std::string("pw"); }, store_config, &ReadyEntropy,
      [](const GatekeeperClientConfig&, const std::string&, const std::string&)
          -> AuthResult {
        throw IdentityManagerError(IdentityErrorCode::AuthServerUnavailable,
                                   "auth unavailable");
      });

  std::atomic<bool> saw_unreachable{false};
  manager.on_security_alert([&](AlertType alert) {
    if (alert == AlertType::AuthServerUnreachable) {
      saw_unreachable.store(true);
    }
  });

  RotationPolicy policy;
  policy.refresh_ratio = 0.0;
  policy.minimum_interval = std::chrono::milliseconds(10);
  policy.retry_initial = std::chrono::milliseconds(5);
  policy.retry_max = std::chrono::milliseconds(20);
  policy.max_retries = 2;
  policy.lkg_grace_period = std::chrono::seconds(60);

  GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;
  manager.StartRotation(config, "alice", policy);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!saw_unreachable.load() && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  manager.StopRotation();
  EXPECT_TRUE(saw_unreachable.load());
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);
}

TEST(RotationWorkerTest, KeepsLkgAndRecoversAfterOutage) {
  std::atomic<int> calls{0};
  IdentityManager manager(
      [] { return std::string("pw"); }, std::nullopt, &ReadyEntropy,
      [&](const GatekeeperClientConfig&, const std::string&, const std::string&)
          -> AuthResult {
        const int current = ++calls;
        AuthResult result;
        result.user_uuid = "user-1";
        result.issued_at = std::chrono::system_clock::now();
        if (current == 1) {
          result.refresh_token = "refresh-initial";
          result.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(30);
          return result;
        }
        if (current <= 3) {
          throw IdentityManagerError(IdentityErrorCode::AuthServerUnavailable,
                                     "temporary outage");
        }
        result.refresh_token = "refresh-rotated";
        result.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
        return result;
      });

  GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;
  (void)manager.Authenticate(config, "alice", "pw");

  std::atomic<int> rotation_successes{0};
  std::atomic<int> unreachable_alerts{0};
  manager.on_rotation([&]() { rotation_successes.fetch_add(1); });
  manager.on_security_alert([&](AlertType alert) {
    if (alert == AlertType::AuthServerUnreachable) {
      unreachable_alerts.fetch_add(1);
    }
  });

  RotationPolicy policy;
  policy.refresh_ratio = 0.0;
  policy.minimum_interval = std::chrono::milliseconds(10);
  policy.retry_initial = std::chrono::milliseconds(80);
  policy.retry_max = std::chrono::milliseconds(80);
  policy.max_retries = 4;
  policy.lkg_grace_period = std::chrono::seconds(60);
  manager.StartRotation(config, "alice", policy);

  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  const auto early = manager.GetPersistedIdentity();
  ASSERT_TRUE(early.has_value());
  EXPECT_EQ(early->refresh_token, "refresh-initial");
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < deadline) {
    const auto current = manager.GetPersistedIdentity();
    if (current.has_value() && current->refresh_token == "refresh-rotated") {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  manager.StopRotation();
  const auto final = manager.GetPersistedIdentity();
  ASSERT_TRUE(final.has_value());
  EXPECT_EQ(final->refresh_token, "refresh-rotated");
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);
  EXPECT_GT(rotation_successes.load(), 0);
  EXPECT_GT(unreachable_alerts.load(), 0);
}

TEST(RotationWorkerTest, LifecycleIssuePathUpdatesSecurityContext) {
  const auto initial_pair = GenerateSelfSigned();
  const auto rotated_pair = GenerateSelfSigned();

  std::atomic<int> issue_calls{0};
  std::atomic<int> renew_calls{0};
  std::atomic<bool> saw_serial_update{false};
  std::string observed_serial;

  IdentityManager manager(
      [] { return std::string("pw"); }, std::nullopt, &ReadyEntropy,
      [&](const GatekeeperClientConfig&, const std::string&, const std::string&)
          -> AuthResult {
        AuthResult result;
        result.user_uuid = "user-1";
        result.refresh_token = "refresh-token";
        result.issued_at = std::chrono::system_clock::now();
        result.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
        return result;
      },
      [&](const NotaryClientConfig&, std::string_view, const std::string&,
          std::uint32_t, const std::string&) -> CertificateMaterial {
        ++issue_calls;
        CertificateMaterial material;
        material.certificate_serial = "serial-issued";
        material.certificate_pem = rotated_pair.cert_pem;
        material.certificate_chain_pem = rotated_pair.cert_pem;
        material.not_before = std::chrono::system_clock::now();
        material.not_after = material.not_before + std::chrono::hours(1);
        return material;
      },
      [&](const NotaryClientConfig&, std::string_view, const std::string&,
          std::uint32_t, const std::string&) -> CertificateMaterial {
        ++renew_calls;
        CertificateMaterial material;
        material.certificate_serial = "serial-renewed";
        material.certificate_pem = rotated_pair.cert_pem;
        material.certificate_chain_pem = rotated_pair.cert_pem;
        material.not_before = std::chrono::system_clock::now();
        material.not_after = material.not_before + std::chrono::hours(1);
        return material;
      });

  GatekeeperClientConfig gatekeeper;
  gatekeeper.target = "127.0.0.1:50051";
  gatekeeper.allow_insecure = true;
  ASSERT_NO_THROW(static_cast<void>(manager.Authenticate(gatekeeper, "alice", "pw")));

  TransportContextConfig initial_context;
  initial_context.certificate_chain_pem = initial_pair.cert_pem + initial_pair.cert_pem;
  initial_context.private_key_pem = initial_pair.key_pem;
  initial_context.alpn = "h3";
  manager.UpdateSecurityContext(initial_context);
  const auto before_ctx = manager.get_quic_context().ctx;
  ASSERT_NE(before_ctx, nullptr);

  CertificateLifecycleConfig lifecycle;
  lifecycle.notary.target = "127.0.0.1:50052";
  lifecycle.notary.allow_insecure = true;
  lifecycle.csr_provider = [] { return std::string("csr-der"); };
  lifecycle.private_key_provider = [rotated_pair] { return rotated_pair.key_pem; };
  lifecycle.requested_ttl_seconds = 600;
  lifecycle.alpn = "h3";
  lifecycle.serial_observer = [&](const std::string& serial) {
    observed_serial = serial;
    saw_serial_update.store(true);
  };
  manager.ConfigureCertificateLifecycle(lifecycle);

  RotationPolicy policy;
  policy.refresh_ratio = 0.0;
  policy.minimum_interval = std::chrono::milliseconds(10);
  policy.retry_initial = std::chrono::milliseconds(10);
  policy.retry_max = std::chrono::milliseconds(20);
  policy.max_retries = 2;
  policy.lkg_grace_period = std::chrono::seconds(60);
  manager.StartRotation(gatekeeper, "alice", policy);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!saw_serial_update.load() && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  manager.StopRotation();

  EXPECT_TRUE(saw_serial_update.load());
  EXPECT_EQ(observed_serial, "serial-issued");
  EXPECT_GT(issue_calls.load(), 0);
  EXPECT_EQ(renew_calls.load(), 0);
  EXPECT_NE(manager.get_quic_context().ctx, before_ctx);
}

TEST(RotationWorkerTest, LifecycleFailureKeepsLastKnownGoodContext) {
  const auto initial_pair = GenerateSelfSigned();
  const auto rotated_pair = GenerateSelfSigned();

  std::atomic<int> issue_calls{0};
  std::vector<AnalyticsEvent> events;

  IdentityManager manager(
      [] { return std::string("pw"); }, std::nullopt, &ReadyEntropy,
      [&](const GatekeeperClientConfig&, const std::string&, const std::string&)
          -> AuthResult {
        AuthResult result;
        result.user_uuid = "user-1";
        result.refresh_token = "refresh-token";
        result.issued_at = std::chrono::system_clock::now();
        result.expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
        return result;
      },
      [&](const NotaryClientConfig&, std::string_view, const std::string&,
          std::uint32_t, const std::string&) -> CertificateMaterial {
        ++issue_calls;
        CertificateMaterial material;
        material.certificate_serial = "serial-issued";
        material.certificate_pem = rotated_pair.cert_pem;
        material.certificate_chain_pem = "";
        material.not_before = std::chrono::system_clock::now();
        material.not_after = material.not_before + std::chrono::hours(1);
        return material;
      });

  manager.on_analytics([&](const AnalyticsEvent& event) { events.push_back(event); });

  GatekeeperClientConfig gatekeeper;
  gatekeeper.target = "127.0.0.1:50051";
  gatekeeper.allow_insecure = true;
  ASSERT_NO_THROW(static_cast<void>(manager.Authenticate(gatekeeper, "alice", "pw")));

  TransportContextConfig initial_context;
  initial_context.certificate_chain_pem = initial_pair.cert_pem + initial_pair.cert_pem;
  initial_context.private_key_pem = initial_pair.key_pem;
  initial_context.alpn = "h3";
  manager.UpdateSecurityContext(initial_context);
  const auto before_ctx = manager.get_quic_context().ctx;
  ASSERT_NE(before_ctx, nullptr);

  CertificateLifecycleConfig lifecycle;
  lifecycle.notary.target = "127.0.0.1:50052";
  lifecycle.notary.allow_insecure = true;
  lifecycle.csr_provider = [] { return std::string("csr-der"); };
  lifecycle.private_key_provider = [rotated_pair] { return rotated_pair.key_pem; };
  lifecycle.requested_ttl_seconds = 600;
  lifecycle.alpn = "h3";
  manager.ConfigureCertificateLifecycle(lifecycle);

  RotationPolicy policy;
  policy.refresh_ratio = 0.0;
  policy.minimum_interval = std::chrono::milliseconds(10);
  policy.retry_initial = std::chrono::milliseconds(10);
  policy.retry_max = std::chrono::milliseconds(20);
  policy.max_retries = 1;
  policy.lkg_grace_period = std::chrono::seconds(60);
  manager.StartRotation(gatekeeper, "alice", policy);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (issue_calls.load() == 0 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  manager.StopRotation();

  EXPECT_GT(issue_calls.load(), 0);
  EXPECT_EQ(manager.get_quic_context().ctx, before_ctx);
  EXPECT_EQ(manager.GetState(), IdentityState::Ready);

  bool saw_notary_rotation_failure = false;
  for (const auto& event : events) {
    if (event.type == AnalyticsEventType::RotationFailure &&
        event.detail == "notary_request_failed") {
      saw_notary_rotation_failure = true;
      break;
    }
  }
  EXPECT_TRUE(saw_notary_rotation_failure);
}

TEST(TransportContextTest, RejectsMissingAlpn) {
  const auto pair = GenerateSelfSigned();
  IdentityManager manager(CredentialProvider{});
  TransportContextConfig config;
  config.certificate_chain_pem = pair.cert_pem + pair.cert_pem;
  config.private_key_pem = pair.key_pem;
  EXPECT_THROW(manager.UpdateSecurityContext(config), std::runtime_error);
}

TEST(TransportContextTest, RejectsChainWithoutIntermediate) {
  const auto pair = GenerateSelfSigned();
  IdentityManager manager(CredentialProvider{});
  TransportContextConfig config;
  config.certificate_chain_pem = pair.cert_pem;
  config.private_key_pem = pair.key_pem;
  config.alpn = "h3";
  EXPECT_THROW(manager.UpdateSecurityContext(config), std::runtime_error);
}

TEST(TransportContextTest, ConcurrentReadsDuringSwapAreSafe) {
  const auto pair = GenerateSelfSigned();
  IdentityManager manager(CredentialProvider{});

  TransportContextConfig config;
  config.certificate_chain_pem = pair.cert_pem + pair.cert_pem;
  config.private_key_pem = pair.key_pem;
  config.alpn = "h3";
  manager.UpdateSecurityContext(config);

  std::atomic<int> reads{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&]() {
      for (int j = 0; j < 500; ++j) {
        const SecurityContext context = manager.get_quic_context();
        if (context.ctx != nullptr) {
          reads.fetch_add(1);
        }
      }
    });
  }

  std::thread writer([&]() {
    for (int i = 0; i < 100; ++i) {
      manager.UpdateSecurityContext(config);
    }
  });

  writer.join();
  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_GT(reads.load(), 0);
  EXPECT_NE(manager.get_quic_context().ctx, nullptr);
}

TEST(AnalyticsTest, FailureEventsDoNotExposePasswordMaterial) {
  const std::string password = "super-secret-password";
  IdentityManager manager(
      [] { return std::string("unused"); }, std::nullopt, &ReadyEntropy,
      [&](const GatekeeperClientConfig&, const std::string&, const std::string&)
          -> AuthResult {
        throw std::runtime_error("auth failed for super-secret-password");
      });

  std::vector<AnalyticsEvent> events;
  manager.on_analytics([&](const AnalyticsEvent& event) { events.push_back(event); });

  GatekeeperClientConfig config;
  config.target = "127.0.0.1:50051";
  config.allow_insecure = true;

  try {
    static_cast<void>(manager.Authenticate(config, "alice", password));
    FAIL() << "Authenticate should fail";
  } catch (const IdentityManagerError&) {
  }

  ASSERT_FALSE(events.empty());
  for (const auto& event : events) {
    EXPECT_EQ(event.detail.find(password), std::string::npos);
  }
}

}  // namespace
}  // namespace veritas
