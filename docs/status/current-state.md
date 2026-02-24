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
- Dedicated Notary test target is wired as `veritas_notary_tests`.
- Custom Cyrus SASL recipe applies an SRP `sasl_setpass` fix required for
  sasldb provisioning.
- Strict SRP verification is wired in `scripts/test_srp_strict.sh` and the
  `security-srp` GitHub Actions workflow (`.github/workflows/security-srp.yml`).
- CI workflow includes explicit notary coverage lanes:
  - `notary-lifecycle` (runs `veritas_notary_tests`),
  - `tsan-nightly` includes `veritas_notary_tests` in sanitizer scope.
- Redis TLS integration test entrypoint is `scripts/test_redis_tls_integration.sh`.
- Local Gatekeeper/auth demo smoke test entrypoint is `scripts/smoke_auth_demo.sh`.
- Local Notary lifecycle smoke test entrypoint is
  `scripts/smoke_notary_lifecycle.sh`.
- Packaging + verification entrypoints are:
  - `scripts/package.sh`
  - `scripts/verify_package.sh`
- CI packaging lane is `package-artifacts` in
  `.github/workflows/security-srp.yml`, uploading `dist/*` artifacts.
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
- Local Notary lifecycle behavior can be exercised with
  `scripts/smoke_notary_lifecycle.sh`, which runs a deterministic
  `issue -> renew -> revoke -> status` path.

## Component status (summary)

### libveritas (client library)

Implemented
- `IdentityManager` type with basic callbacks and an SRP auth API.
- Explicit identity state model (`Unauthenticated`, `Ready`, `Locked`) with
  machine-readable error codes.
- `LOCKED` state is terminal for lifecycle transitions in-process.
- `AuthFlow`, `GatekeeperClient`, and `SaslClient` for SRP-6a login via Gatekeeper.
- Password buffers are scrubbed with `sodium_memzero` in the SASL client.
- `IdentityManager` performs a non-blocking entropy preflight via `getrandom()`
  before auth and fails fast on retryable/hard entropy errors.
- `SecureBuffer` now uses `sodium_malloc`, attempts `sodium_mlock`, and
  guarantees zeroization on release.
- Rotation worker (`std::jthread`) is implemented in `IdentityManager`:
  - configurable 70/30 scheduling,
  - bounded exponential backoff with jitter,
  - auth-server-unreachable + persistent-rotation-failure alerts,
  - LKG retention during transient failures.
- Transport/security context management now supports:
  - thread-safe `SSL_CTX` swap with shared ownership,
  - TLS 1.3 enforcement in context construction,
  - caller ALPN validation,
  - leaf + intermediate chain ingestion checks.
- Analytics callback hooks are available for auth/rotation outcomes.
- Revocation monitoring is implemented:
  - `StartRevocationMonitor` / `StopRevocationMonitor`,
  - polling `GetTokenStatus`,
  - `TokenRevoked` alert + `LOCKED` transition on revoked status.
- `GatekeeperClientConfig.allow_insecure` is accepted in non-release builds;
  release builds reject insecure transport.
- `GatekeeperClient` now sends protocol version metadata on all Gatekeeper RPCs
  (`x-veritas-protocol`) and validates selected-version metadata
  (`x-veritas-protocol-selected`) on success paths.
- Storage layer includes a `TokenStore` abstraction with:
  - `Libsecret` backend for keyring-backed identity persistence.
  - File fallback backend that requires explicit insecure opt-in.
- `IdentityManager` now integrates persistence when configured with a token store:
  - startup load of persisted identity,
  - save on successful authentication,
  - explicit clear via `ClearPersistedIdentity()`.
- Notary-backed certificate lifecycle is available from `IdentityManager`:
  - `IssueCertificate`,
  - `RenewCertificate`,
  - `RevokeCertificate`,
  - `GetCertificateStatus`.
  - Operations consume the authenticated refresh token from current identity
    state and map Notary failures to
    `IdentityErrorCode::NotaryRequestFailed`.

Placeholders / incomplete
- Rotation worker depends on configured credential provider and auth target.

Aspirational
- Production-grade credential management, rotation, and TLS/QUIC integration.

### protocol (Protobuf)

Implemented
- `protocol/gatekeeper.proto` defines the Gatekeeper gRPC API.
- `protocol/notary.proto` defines a frozen Notary v1 contract for:
  - certificate issuance,
  - renewal,
  - revocation,
  - status lookup.
- `protocol/identity.proto` defines protocol negotiation primitives:
  - `ProtocolVersion`,
  - `NegotiateRequest` / `NegotiateResponse`,
  - `NegotiationResult`,
  - `Identity.Negotiate`.
- Notary contract includes structured service-level enums/messages for:
  - error classification (`NotaryErrorCode`, `NotaryErrorDetail`),
  - certificate lifecycle state (`CertificateStatusState`).

Aspirational
- Full protocol surface for identity, token issuance, and notary services.

### services/shared

Implemented
- `veritas_shared` exposes a build-id helper.
- Shared issuance store abstraction is implemented:
  - issuance record model and storage interface,
  - certificate payload persistence for deterministic idempotent replay,
  - token-hash to certificate-serial linkage,
  - idempotency registration/lookup semantics,
  - revocation-state updates.
- Shared token store abstraction is implemented:
  - token model and storage interface,
  - in-memory tombstone/replay-rejection semantics,
  - Redis URI parsing (`redis://`, `rediss://`) with fail-closed TLS validation.
- Backends:
  - in-memory (thread-safe),
  - Redis (with explicit unavailable errors when Redis support is disabled).
- Gatekeeper token-store compatibility header now forwards to shared token-store
  primitives (`services/gatekeeper/src/token_store.h`).

Aspirational
- Shared DB access and metrics/logging utilities.

### services/notary

Implemented
- Notary gRPC server skeleton is implemented with:
  - fail-closed env config parsing (`NOTARY_*` settings),
  - TLS 1.3-only server credential setup,
  - optional mTLS policy via `NOTARY_TLS_REQUIRE_CLIENT_CERT`,
  - gRPC health service enablement + serving status initialization.
- Notary startup now wires signer + issuance store dependencies:
  - signer config from `NOTARY_SIGNER_CERT`, `NOTARY_SIGNER_KEY`,
    `NOTARY_SIGNER_CHAIN`.
  - shared store backend from `NOTARY_STORE_BACKEND=memory|redis`.
  - Redis store mode requires `NOTARY_STORE_URI`.
- Gatekeeper-backed authorization is wired into mutating Notary RPCs:
  - `NOTARY_GATEKEEPER_TARGET` is required.
  - secure Gatekeeper transport requires `NOTARY_GATEKEEPER_CA_BUNDLE` unless
    `NOTARY_GATEKEEPER_ALLOW_INSECURE=true`.
  - token state mapping:
    - `ACTIVE` -> authz success,
    - `REVOKED` -> `PERMISSION_DENIED`,
    - `UNKNOWN` / `UNSPECIFIED` -> `UNAUTHENTICATED`,
    - Gatekeeper transport unavailable -> `UNAVAILABLE` fail-closed.
- Notary Sprint 1 trust model document exists:
  `docs/architecture/notary-threat-model.md`.
- Notary PKI policy baseline exists:
  `docs/architecture/notary-pki-policy.md`.
- Notary v1 RPC contract is frozen in `protocol/notary.proto`.
- Signer abstraction exists in `services/notary/src/signer.*` with:
  - startup key-material validation hooks (path checks, PEM parse, key/cert
    match),
  - OpenSSL CSR issuance path (signature verification, SAN/CN/key policy, TTL
    clamp, key-usage/EKU extensions),
  - OpenSSL renewal path from existing leaf cert identity material.
- `IssueCertificate` implementation is wired:
  - deterministic request validation (token, CSR, idempotency, minimum TTL),
  - authz enforcement via Gatekeeper token status,
  - signer invocation and leaf + chain response mapping,
  - issuance + idempotency persistence into shared store,
  - idempotent replay for duplicate request key + same token hash.
- `RenewCertificate` implementation is wired:
  - deterministic request validation (token, serial, idempotency, minimum TTL),
  - overlap-window eligibility check (15-minute renewal boundary),
  - active/non-revoked ownership checks via token-hash linkage,
  - signer renewal invocation + persisted renewed record response,
  - idempotent replay for duplicate key and conflict-after-write retry path.
- `RevokeCertificate` implementation is wired:
  - deterministic request validation (token, serial, reason, actor),
  - reason taxonomy validation against constrained revocation codes,
  - authz + ownership checks,
  - revocation persistence with reason/actor/timestamp metadata,
  - deterministic already-revoked response mapping.
- `GetCertificateStatus` implementation is wired:
  - deterministic request validation (serial + refresh token),
  - authz enforcement via Gatekeeper token status,
  - token-hash ownership checks before state return,
  - serial lookup against shared issuance store,
  - lifecycle mapping to active/revoked/expired/unknown states,
  - revocation reason/timestamp return for revoked records.
- Security hardening controls are wired in Notary runtime:
  - fixed-window per-peer rate limiting on issue/renew/revoke/status paths,
  - request-size limits for token/csr/serial/idempotency/reason/actor fields,
  - in-memory security counters (`rate_limited`, `authz_failure`,
    `validation_failure`, `policy_denied`) for future analytics/lockout policy.
- Structured JSON event logging is available for startup and RPC-path events.
- Unit/integration tests cover:
  - config validation and read-file behavior,
  - Gatekeeper token-status authorizer mapping and gRPC path,
  - issue + renew + revoke authz/validation/idempotency/retry paths,
  - rate-limit and malicious oversized-input rejection behavior,
  - lifecycle status-state mapping (active/revoked/expired/unknown),
  - signer validation + issuance + renewal policy paths,
  - startup success with health-service availability,
  - fail-closed startup on invalid signer material,
  - shared issuance store record/idempotency/revocation behavior including
    revocation actor metadata.

Placeholders / incomplete
- Rate-limit/counter configuration is not yet exposed as runtime config.

Aspirational
- Runtime-tunable abuse-control policy and exportable security metrics.

### services/gatekeeper (SASL service)

Implemented
- gRPC server bootstrapped with TLS cert/key from env config (TLS 1.3 only).
- TLS credentials validated at startup (key/cert match, validity window,
  optional chain verification with CA bundle).
- Optional mTLS enforcement with client cert verification.
- `BeginAuth` and `FinishAuth` handlers are present.
- `RevokeToken` and `GetTokenStatus` handlers are present.
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
  - Revocation/tombstone model:
    - revoked tokens carry reason metadata + revocation timestamp.
    - tombstone retention prevents replay of revoked token hashes.
    - status API returns `ACTIVE` / `REVOKED` / `UNKNOWN`.
  - Redis URI parser supports `redis://` and `rediss://` with fail-closed TLS
    validation (`verify_peer=true` requires `cacert`/`cacertdir`; client cert
    auth requires both `cert` and `key`).

Placeholders / incomplete
- SASL verifier provisioning depends on sasldb/auxprop setup in target
  environments (scripted local provisioning is available).
- `BeginAuth` returns mechanism-generated challenge bytes for real users;
  strict constant-size envelope encoding is not implemented.
- Rate-limiter and analytics key caps use code-level defaults; runtime tuning
  via config/env is not implemented.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Tombstone retention is fixed (24h) and not runtime-configurable.
- Redis TLS requires `redis-plus-plus` to be built with TLS support.
- SASL error mapping is limited to a minimal gRPC status translation.
- Unit tests cover fake salt, token hashing, rate limiting, config validation,
  TLS credential validation, token store behavior, and session cache handling.
- Integration tests cover SRP handshake happy path + invalid proof + client
  revocation lock propagation.
- Redis TLS integration tests cover fail-closed behavior for invalid `rediss://`
  configuration and optional external endpoint validation via
  `VERITAS_REDIS_TLS_URI`.

Aspirational
- Streamlined SRP verifier provisioning and server-side rotation policy.
- Exportable rate limiting and analytics metrics.

## Cross-cutting gaps (incomplete)

- SASL verifier provisioning still relies on sasldb/auxprop backend availability.
- External Redis TLS connectivity validation requires a provisioned test endpoint.
- Release transport policy gates were validated in `build_release` via:
  `ConfigTest.LoadConfigRejectsSaslDisabled` and
  `GatekeeperClientTest.InsecureTransportPolicyMatchesBuildType`.

## Scope note

This document reflects **current code** only. Design documents in `.cache/`
describe intended behavior and are not fully implemented.
