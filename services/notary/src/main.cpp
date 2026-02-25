#include <chrono>
#include <exception>
#include <iostream>

#include <grpcpp/support/status.h>

#include "authorizer.h"
#include "config.h"
#include "log_utils.h"
#include "notary_service.h"
#include "security_controls.h"
#include "server.h"
#include "signer.h"
#include "veritas/shared/issuance_store.h"

int main() {
  try {
    const auto config = veritas::notary::LoadConfig();

    std::string gatekeeper_root_ca;
    if (!config.gatekeeper_ca_path.empty()) {
      gatekeeper_root_ca = veritas::notary::ReadFile(config.gatekeeper_ca_path);
    }

    veritas::notary::GatekeeperTokenStatusClientConfig status_client_config;
    status_client_config.target = config.gatekeeper_target;
    status_client_config.root_ca_pem = gatekeeper_root_ca;
    status_client_config.allow_insecure = config.gatekeeper_allow_insecure;
    auto status_client = std::make_shared<veritas::notary::GatekeeperTokenStatusClient>(
        status_client_config);
    auto authorizer = std::make_shared<veritas::notary::RefreshTokenAuthorizer>(
        status_client);

    veritas::shared::SharedStoreConfig store_config;
    store_config.backend =
        config.store_backend == veritas::notary::NotaryStoreBackend::Redis
            ? veritas::shared::SharedStoreBackend::Redis
            : veritas::shared::SharedStoreBackend::InMemory;
    store_config.redis_uri = config.store_uri;

    auto issuance_store = veritas::shared::CreateIssuanceStore(store_config);
    veritas::notary::SignerConfig signer_config;
    signer_config.issuer_cert_path = config.signer_cert_path;
    signer_config.issuer_key_path = config.signer_key_path;
    signer_config.issuer_chain_path = config.signer_chain_path;
    signer_config.not_before_skew =
        std::chrono::seconds(config.signer_not_before_skew_seconds);
    signer_config.hash_algorithm = config.signer_hash_algorithm;
    auto signer =
        std::make_shared<veritas::notary::OpenSslSigner>(std::move(signer_config));

    veritas::notary::FixedWindowRateLimiterConfig peer_limiter_config;
    peer_limiter_config.max_requests_per_window =
        config.rate_limit_peer_max_requests;
    peer_limiter_config.max_keys = config.rate_limit_peer_max_keys;
    peer_limiter_config.window =
        std::chrono::seconds(config.rate_limit_peer_window_seconds);
    auto peer_limiter = std::make_shared<veritas::notary::FixedWindowRateLimiter>(
        peer_limiter_config);

    veritas::notary::FixedWindowRateLimiterConfig identity_limiter_config;
    identity_limiter_config.max_requests_per_window =
        config.rate_limit_identity_max_requests;
    identity_limiter_config.max_keys = config.rate_limit_identity_max_keys;
    identity_limiter_config.window =
        std::chrono::seconds(config.rate_limit_identity_window_seconds);
    auto identity_limiter =
        std::make_shared<veritas::notary::FixedWindowRateLimiter>(
            identity_limiter_config);

    veritas::notary::RevokedTokenAbusePolicy abuse_policy;
    abuse_policy.threshold = config.revoked_token_abuse_threshold;
    abuse_policy.window =
        std::chrono::seconds(config.revoked_token_abuse_window_seconds);
    abuse_policy.enforcement_enabled =
        config.revoked_token_enforcement_enabled;
    abuse_policy.enforcement_duration = std::chrono::seconds(
        config.revoked_token_enforcement_duration_seconds);
    auto revoked_token_tracker =
        std::make_shared<veritas::notary::RevokedTokenAbuseTracker>(
            abuse_policy);

    veritas::notary::NotaryServiceImpl service(
        authorizer, signer, issuance_store, peer_limiter, identity_limiter,
        nullptr, revoked_token_tracker);
    auto runtime = veritas::notary::StartNotaryServer(config, &service);
    veritas::notary::LogNotaryEvent("Startup", grpc::Status::OK,
                                    runtime.bound_addr);
    runtime.server->Wait();
  } catch (const std::exception& ex) {
    std::cerr << "Notary startup failed: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
