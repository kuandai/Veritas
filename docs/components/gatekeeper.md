# Gatekeeper Service

## Purpose

Authenticate clients and issue refresh tokens via a gRPC interface.

## Current implementation

- gRPC server starts with TLS key/cert from env config.
- `BeginAuth` / `FinishAuth` handlers exist.
- Per-IP rate limiting (5/minute).
- Structured logging to stdout (`timestamp`, `ip`, `action`, `status`,
  optional `user_uuid`).
- In-memory auth analytics counters (success/failure per IP and per UUID).
- Mock SASL flow:
  - Deterministic fake salt (HMAC).
  - Session ids stored in a TTL cache.
  - Mock SRP parameters returned.
  - Refresh token issuance + SHA-256 hashing stored in an in-memory token store.

## Placeholders / incomplete

- **SASL/SRP-6a handshake is not implemented** (mock only).
- No verifier lookup or proof validation.
- Token store is in-memory only (no persistence).
- TLS is not constrained to 1.3, and no additional cert validation policy.
- gRPC error mapping is basic (no service-level mapping table).
- No unit/integration tests.

## Aspirational

- Full SRP-6a handshake and verifier storage.
- Redis-backed token store (shared with Notary).
- TLS 1.3-only policy and hardened mTLS.
- Exportable metrics for rate limiting and analytics.
