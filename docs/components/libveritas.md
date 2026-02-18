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
- Client-side SRP-6a handshake is implemented under `libveritas/src/auth/`:
  - `SaslClient` wraps Cyrus SASL SRP and scrubs password buffers.
  - `GatekeeperClient` wraps gRPC BeginAuth/FinishAuth calls.
  - `AuthFlow` orchestrates SRP proofs across gRPC + SASL.
  - `GatekeeperClientConfig.allow_insecure` is accepted in non-release builds;
    release builds reject insecure transport.
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
- `get_quic_context()` returns a default/empty `SecurityContext`.

## Placeholders / incomplete

- No transport integration beyond placeholder context accessor.
- No certificate rotation worker.
- Callbacks are stored but not invoked.
- `SecurityContext` remains a thin wrapper over `SSL_CTX*`.
- Auth API is synchronous only; no retry or backoff logic yet.

## Aspirational

- Production identity lifecycle management and automated rotation.
- Safe, opinionated TLS/QUIC setup for clients.
