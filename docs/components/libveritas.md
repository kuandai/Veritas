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
  - Optional certificate lifecycle coupling:
    - `ConfigureCertificateLifecycle(...)` binds Notary issue/renew to the
      rotation worker,
    - successful token refresh can trigger Notary issue/renew and context swap,
    - context swap is performed only after new cert/private-key context
      validation succeeds,
    - failed cert lifecycle updates preserve the last-known-good context and
      are treated as rotation failures for backoff/alerts.
- Revocation lifecycle:
  - `StartRevocationMonitor`/`StopRevocationMonitor` polling loop.
  - Client-side `GetTokenStatus` checks via Gatekeeper.
  - `TokenRevoked` alert emission and `LOCKED` transition on revocation.
- Notary-backed certificate lifecycle path is implemented:
  - `IssueCertificate(...)`
  - `RenewCertificate(...)`
  - `RevokeCertificate(...)`
  - `GetCertificateStatus(...)`
  - Uses the authenticated refresh token from `IdentityManager` state.
  - Enforces `IdentityState::Ready` before Notary operations.
  - Maps Notary failures to `IdentityErrorCode::NotaryRequestFailed`.
  - Successful issue/renew operations update in-memory active certificate serial
    tracking used by background lifecycle rotation.
- Transport context hardening:
  - Thread-safe `SSL_CTX` swap with reader-safe shared ownership.
  - TLS 1.3-only context construction.
  - Caller-provided ALPN is required and validated.
  - Certificate input requires leaf + intermediate chain ingestion.
- `get_quic_context()` returns the current shared `SecurityContext`.

## Placeholders / incomplete

- Rotation worker depends on configured credential provider and auth target.

## Aspirational

- Production identity lifecycle management and automated rotation.
- Safe, opinionated TLS/QUIC setup for clients.
