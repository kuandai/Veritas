# libveritas (Client Library)

## Purpose

Provide C++ clients with a simple integration point for identity material,
token rotation callbacks, and a security context for transport layers (TLS/QUIC).

## Current implementation

- `IdentityManager` exists with callback registration and a minimal auth API:
  - `Authenticate(config, username, password)`
  - `Authenticate(config, username)` (password pulled from `CredentialProvider`)
  - Explicit identity lifecycle states:
    - `Unauthenticated`
    - `Ready`
    - `Locked` (terminal until process restart)
  - Machine-readable error codes for auth/lifecycle failures.
  - Thread-safe state/error accessors via shared mutex.
  - Analytics/security callback hooks for auth and rotation outcomes.
- Client-side SRP-6a handshake is implemented under `libveritas/src/auth/`:
  - `SaslClient` wraps Cyrus SASL SRP and scrubs password buffers.
  - `GatekeeperClient` wraps gRPC BeginAuth/FinishAuth calls.
  - `AuthFlow` orchestrates SRP proofs across gRPC + SASL.
  - `GatekeeperClientConfig.allow_insecure` is accepted in non-release builds;
    release builds reject insecure transport.
  - Gatekeeper protocol metadata is sent on every RPC:
    `x-veritas-protocol=<major>.<minor>` (defaults `1.0`), and selected
    version metadata is validated on successful responses.
- Client storage layer now includes a `TokenStore` abstraction with:
  - `Libsecret` backend for secure keyring-backed persistence.
  - File fallback backend gated by explicit opt-in
    (`allow_insecure_fallback=true`).
- `IdentityManager` persistence integration:
  - Loads persisted identity at startup when a token store is configured.
  - Persists successful auth result (`user_uuid`, refresh token, expiry).
  - Supports explicit persisted-identity clearing (`ClearPersistedIdentity()`).
- Entropy hardening:
  - Authentication now performs a non-blocking `getrandom()` preflight.
  - Retryable entropy starvation and hard entropy failures map to
    `IdentityErrorCode::EntropyUnavailable`.
- Secure in-memory handling:
  - `SecureBuffer` uses `sodium_malloc`.
  - Attempts `sodium_mlock` when available.
  - Guarantees zeroization before release across success and failure paths.
- Rotation lifecycle:
  - `StartRotation`/`StopRotation` based on a `std::jthread` worker.
  - Configurable 70/30 refresh schedule (`RotationPolicy.refresh_ratio`).
  - Exponential backoff with jitter and bounded retry budget.
  - LKG behavior during transient failures and lock transition after
    grace-window exhaustion.
  - Auth-server-unreachable and persistent-rotation-failure alerts.
- Revocation lifecycle:
  - `StartRevocationMonitor`/`StopRevocationMonitor` polling loop.
  - Client-side `GetTokenStatus` checks via Gatekeeper.
  - `TokenRevoked` alert emission and `LOCKED` transition on revocation.
- Transport context hardening:
  - Thread-safe `SSL_CTX` swap with reader-safe shared ownership.
  - TLS 1.3-only context construction.
  - Caller-provided ALPN is required and validated.
  - Certificate input requires leaf + intermediate chain ingestion.
- `get_quic_context()` returns the current shared `SecurityContext`.

## Placeholders / incomplete

- Rotation worker depends on configured credential provider and auth target.
- Credential-provider abstraction is local-only (no Notary integration yet).

## Aspirational

- Production identity lifecycle management and automated rotation.
- Safe, opinionated TLS/QUIC setup for clients.
