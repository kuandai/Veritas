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
  - Refresh token issuance + SHA-256 hashing stored in Redis when
    `TOKEN_STORE_URI` is set (in-memory fallback otherwise).

## Placeholders / incomplete

- **SASL/SRP-6a handshake is not implemented** (mock only).
- No verifier lookup or proof validation.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Redis TLS (`rediss://`) is not supported yet.
- TLS is not constrained to 1.3, and no additional cert validation policy.
- gRPC error mapping is basic (no service-level mapping table).
- Unit tests exist for fake salt, token hashing, and rate limiting; integration
  tests are still missing.

## Aspirational

- Full SRP-6a handshake and verifier storage.
- Redis-backed token store shared with Notary.
- TLS 1.3-only policy and hardened mTLS.
- Exportable metrics for rate limiting and analytics.
