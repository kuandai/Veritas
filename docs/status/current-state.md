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
**Aspirational:** replace `file(GLOB_RECURSE ...)` with explicit source lists
as the codebase stabilizes.

## Component status (summary)

### libveritas (client library)

Implemented
- `IdentityManager` type with basic callbacks.

Placeholders / incomplete
- `SecurityContext` is empty beyond an `SSL_CTX*`.
- `get_quic_context()` returns a default/empty context.
- Callbacks are stored but not invoked.
- No certificate rotation or transport integration.

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
- gRPC server bootstrapped with TLS cert/key from env config.
- `BeginAuth` and `FinishAuth` handlers are present.
- Per-IP rate limiting (5/minute).
- Structured auth event logging to stdout (`timestamp`, `ip`, `action`,
  `status`, `user_uuid?`).
- In-memory auth analytics counters (success/failure per IP and UUID).
- SASL SRP-6a handshake via Cyrus SASL:
  - SASL server challenge returned in `server_public` (opaque payload).
  - Deterministic fake salts for unknown users.
  - SASL server final payload returned in `server_proof`.
  - Session ids stored in a TTL cache.
  - Refresh token issuance + SHA-256 hashing, persisted to Redis when
    `TOKEN_STORE_URI` is set (in-memory fallback otherwise).

Placeholders / incomplete
- SASL verifier provisioning depends on external sasldb/auxprop setup.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Redis TLS (`rediss://`) is not supported yet.
- TLS is not constrained to 1.3; no additional cert validation policy.
- SASL error mapping is limited to a minimal gRPC status translation.
- Unit tests exist for fake salt, token hashing, and rate limiting; integration
  tests are still missing.

Aspirational
- Streamlined SRP verifier provisioning and server-side rotation policy.
- Redis-backed token store shared with Notary.
- TLS 1.3-only policy and hardened mTLS options.
- Exportable rate limiting and analytics metrics.

## Cross-cutting gaps (incomplete)

- SASL verifier provisioning and end-to-end SRP integration tests.
- Token store persistence and revocation flows (beyond current Redis adapter).
- TLS 1.3 enforcement and stronger certificate validation.
- Shared storage layer and cross-service integration.
- Integration tests for security-critical flows.

## Scope note

This document reflects **current code** only. Design documents in `.cache/`
describe intended behavior and are not fully implemented.
