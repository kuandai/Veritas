# Current State

Snapshot of the repository as implemented today. Each section explicitly calls
out **placeholders**, **incomplete implementations**, and **aspirational**
items.

## Repository layout (summary)

- `libveritas/`: C++ client library.
- `services/`: backend services (Gatekeeper, Notary, shared utilities).
- `protocol/`: Protobuf definitions (generated artifacts appear under
  `build/protocol/`).
- `docs/`: project documentation.

## Build and tooling

- CMake + Conan, C++20.
- gRPC/Protobuf code generation is wired through the `protocol` target.
- Custom Cyrus SASL recipe applies an SRP `sasl_setpass` fix required for
  sasldb provisioning.
- Strict SRP verification is wired in `scripts/test_srp_strict.sh` and the
  `security-srp` GitHub Actions workflow (`.github/workflows/security-srp.yml`).
- Redis TLS integration test entrypoint is `scripts/test_redis_tls_integration.sh`.
- Local Gatekeeper/auth demo smoke test entrypoint is `scripts/smoke_auth_demo.sh`.
**Aspirational:** replace `file(GLOB_RECURSE ...)` with explicit source lists
as the codebase stabilizes.

## Deployment testing (latest)

- Local Gatekeeper + demo client deployment can be exercised with
  `scripts/smoke_auth_demo.sh`. SRP login succeeds when:
  - `SASL_REALM` is set and the client uses a realm-qualified authid
    (the demo now appends `@<realm>` automatically).
  - `SASL_CONF_PATH` points at a directory containing
    `veritas_gatekeeper.conf`.
  - The server accepts `SASL_CONTINUE` with a final server proof as
    success.

## Component status (summary)

### libveritas (client library)

Implemented
- `IdentityManager` type with basic callbacks and an SRP auth API.
- `AuthFlow`, `GatekeeperClient`, and `SaslClient` for SRP-6a login via Gatekeeper.
- Password buffers are scrubbed with `sodium_memzero` in the SASL client.
- `GatekeeperClientConfig.allow_insecure` is accepted in non-release builds;
  release builds reject insecure transport.
- Storage layer includes a `TokenStore` abstraction with:
  - `Libsecret` backend for keyring-backed identity persistence.
  - File fallback backend that requires explicit insecure opt-in.

Placeholders / incomplete
- `SecurityContext` is empty beyond an `SSL_CTX*`.
- `get_quic_context()` returns a default/empty context.
- Callbacks are stored but not invoked.
- No certificate rotation or transport integration.
- Token storage is not yet wired into `IdentityManager` authentication lifecycle.
- No refresh scheduling/rotation lifecycle yet.

Aspirational
- Production-grade credential management, rotation, and TLS/QUIC integration.

### protocol (Protobuf)

Implemented
- `protocol/gatekeeper.proto` defines the Gatekeeper gRPC API.

Placeholders / incomplete
- `protocol/identity.proto` is explicitly a placeholder.
- No explicit versioning or error model beyond gRPC status codes.

Aspirational
- Full protocol surface for identity, token issuance, and notary services.

### services/shared

Implemented
- `veritas_shared` exposes a build-id helper.

Placeholders / incomplete
- No shared data access layer.

Aspirational
- Shared DB access, token store adapters, and metrics/logging utilities.

### services/notary

Implemented
- Minimal CLI that prints the shared build id.

Placeholders / incomplete
- No notary logic implemented.

Aspirational
- Notary service with shared token store integration.

### services/gatekeeper (SASL service)

Implemented
- gRPC server bootstrapped with TLS cert/key from env config (TLS 1.3 only).
- TLS credentials validated at startup (key/cert match, validity window,
  optional chain verification with CA bundle).
- Optional mTLS enforcement with client cert verification.
- `BeginAuth` and `FinishAuth` handlers are present.
- Per-IP rate limiting (5/minute) with oldest-bucket eviction when the
  in-memory key cap is reached (default: 10,000 keys).
- Structured auth event logging to stdout (`timestamp`, `ip`, `action`,
  `status`, `user_uuid?`) with JSON escaping for untrusted field values.
- In-memory auth analytics counters (success/failure per IP and UUID) with
  bounded key cardinality and oldest-entry eviction (default: 10,000 keys per
  map).
- SASL SRP-6a handshake via Cyrus SASL:
  - SASL server challenge returned in `server_public` (opaque payload).
  - Deterministic fake salts in all `BeginAuth` responses.
  - `BeginAuth` enforces a minimum response-duration budget (default: 8ms).
  - Unknown-user fake challenges are sized using an observed challenge-size
    baseline (default seed: 512 bytes).
  - SASL server final payload returned in `server_proof`.
  - `BeginAuthRequest.client_start` carries the SASL client initial response.
  - Runtime `SASL_ENABLE=false` is rejected at startup in this build.
  - Session ids stored in a TTL cache and consumed atomically on `FinishAuth`.
  - Refresh token issuance + SHA-256 hashing, persisted to Redis when
    `TOKEN_STORE_URI` is set (in-memory fallback otherwise).
  - Redis URI parser supports `redis://` and `rediss://` with fail-closed TLS
    validation (`verify_peer=true` requires `cacert`/`cacertdir`; client cert
    auth requires both `cert` and `key`).

Placeholders / incomplete
- SASL verifier provisioning depends on external sasldb/auxprop setup.
- `BeginAuth` returns mechanism-generated challenge bytes for real users;
  strict constant-size envelope encoding is not implemented.
- Rate-limiter and analytics key caps use code-level defaults; runtime tuning
  via config/env is not implemented.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Redis TLS requires `redis-plus-plus` to be built with TLS support.
- SASL error mapping is limited to a minimal gRPC status translation.
- Unit tests cover fake salt, token hashing, rate limiting, config validation,
  TLS credential validation, token store behavior, and session cache handling.
- Integration tests cover SRP handshake happy path + invalid proof.
- Redis TLS integration tests cover fail-closed behavior for invalid `rediss://`
  configuration and optional external endpoint validation via
  `VERITAS_REDIS_TLS_URI`.

Aspirational
- Streamlined SRP verifier provisioning and server-side rotation policy.
- Redis-backed token store shared with Notary.
- Exportable rate limiting and analytics metrics.

## Cross-cutting gaps (incomplete)

- SASL verifier provisioning (still external sasldb/auxprop tooling).
- Token store persistence and revocation flows (beyond current Redis adapter).
- Shared storage layer and cross-service integration.
- TSAN lane is not wired in CI (strict SRP lane is wired).
- External Redis TLS connectivity validation requires a provisioned test endpoint.
- Release transport policy gates were validated in `build_release` via:
  `ConfigTest.LoadConfigRejectsSaslDisabled` and
  `GatekeeperClientTest.InsecureTransportPolicyMatchesBuildType`.

## Scope note

This document reflects **current code** only. Design documents in `.cache/`
describe intended behavior and are not fully implemented.
