# Codebase State (Current)

This document summarizes the **current** state of the repository, with explicit
labels for placeholders, incomplete implementations, and aspirational features.

## Repository layout

- `libveritas/`: C++ client library (currently skeletal).
- `services/`: backend services (Gatekeeper, Notary, shared utilities).
- `protocol/`: Protobuf definitions and generated artifacts at build time.
- `docs/`: project documentation (this file).

## Build system

- CMake + Conan with C++20.
- gRPC + Protobuf are configured via Conan and the protocol target generates
  `.pb.*` + `.grpc.pb.*` outputs into `build/protocol/`.

## Components

### libveritas (client library)

Current state:
- `IdentityManager` exists with basic callbacks and a placeholder
  `get_quic_context()` that returns an empty `SecurityContext`.

**Placeholders / incomplete**
- `SecurityContext` is currently empty (`SSL_CTX*` only).
- No transport integration, rotation, or certificate handling logic yet.
- Callbacks are stored but never invoked.

**Aspirational**
- A production `IdentityManager` that manages credentials, rotation, and client
  TLS/QUIC contexts.

### protocol (Protobuf)

Current state:
- `protocol/gatekeeper.proto` defines the Gatekeeper gRPC service and messages.
- `protocol/identity.proto` contains a **placeholder** message.

**Placeholders / incomplete**
- `identity.proto` is explicitly a placeholder definition.
- No protocol versioning or error model mapping beyond gRPC status codes.

**Aspirational**
- Full protocol set for identity, token issuance, and notary services.

### services/shared

Current state:
- `veritas_shared` library exposes a `shared_build_id()` string.

**Placeholders / incomplete**
- No shared data access layer yet.

**Aspirational**
- Shared DB access, token store adapters, metrics/logging utilities.

### services/notary

Current state:
- Minimal CLI that prints the shared build id.

**Placeholders / incomplete**
- No notary logic implemented.

**Aspirational**
- Notary service implementation with shared token store integration.

### services/gatekeeper (SASL service)

Current state:
- gRPC server bootstraps with TLS key/cert files from env config.
- `BeginAuth` and `FinishAuth` handlers exist.
- Per-IP rate limiting (5/min) is enforced.
- Structured auth event logging (`timestamp`, `ip`, `action`, `status`,
  `user_uuid?`) to stdout.
- In-memory auth analytics counters (success/failure per IP and UUID).
- Mock SASL flow:
  - Generates a deterministic fake salt (HMAC).
  - Creates a session id and stores it in a TTL cache.
  - Returns mock SRP parameters.
  - Issues a refresh token (random bytes), hashes it with SHA-256, and stores
    the record in an **in-memory** token store.

**Placeholders / incomplete**
- **SASL/SRP-6a is not implemented.** Current flow is a mock placeholder.
- Token store is in-memory only (no persistence).
- No verifier lookup or proof validation.
- TLS **is not** forced to TLS 1.3; no cert validation policy beyond loading
  PEM files.
- No gRPC error mapping beyond basic statuses returned in handlers.
- No unit/integration tests for Gatekeeper.

**Aspirational**
- Full SRP-6a SASL handshake and verifier storage.
- Redis-backed token store (shared with Notary).
- TLS 1.3-only policy and hardened mTLS options.
- Rate limiting + analytics exported as real metrics.

## Summary of missing or incomplete features

- SRP/SASL handshake, verifier lookup, and proof verification.
- Token store persistence and revocation flows.
- TLS 1.3 enforcement and stronger certificate validation.
- Shared storage layer and cross-service integration.
- Tests for security-critical flows.

## Notes

This document reflects **current code** only. Design documents in `.cache/`
describe intended behavior; they are not yet fully implemented.
