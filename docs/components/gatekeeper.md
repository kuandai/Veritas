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
- SASL SRP-6a via Cyrus SASL:
  - `BeginAuth` seeds a SASL session and returns the SASL server challenge in
    `server_public` (opaque payload).
  - Unknown users receive a deterministic fake salt plus a fake challenge to
    reduce enumeration signals.
  - For real users the `salt` field is empty; clients must use the SASL
    challenge payload to compute proofs.
  - `FinishAuth` validates the client proof via SASL and returns the SASL
    server final payload in `server_proof`.
- Session ids stored in a TTL cache.
- Refresh token issuance + SHA-256 hashing stored in Redis when
  `TOKEN_STORE_URI` is set (in-memory fallback otherwise).

## Configuration notes

SASL behavior is controlled by environment variables:

- `SASL_ENABLE` (default: true)
- `SASL_SERVICE` (default: `veritas_gatekeeper`)
- `SASL_MECH_LIST` (default: `SRP`)
- `SASL_CONF_PATH` (optional)
- `SASL_PLUGIN_PATH` (optional)
- `SASL_DBNAME` (optional, sasldb path)
- `SASL_REALM` (optional)

## Placeholders / incomplete

- SASL SRP handshake depends on external SASL configuration (sasldb/auxprop);
  verifier provisioning is not automated.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Redis TLS (`rediss://`) is not supported yet.
- TLS is not constrained to 1.3, and no additional cert validation policy.
- gRPC error mapping is limited to current SASL status handling.
- Unit tests exist for fake salt, token hashing, and rate limiting; integration
  tests are still missing.

## Aspirational

- Streamlined SRP verifier provisioning and server-side rotation policy.
- Redis-backed token store shared with Notary.
- TLS 1.3-only policy and hardened mTLS.
- Exportable metrics for rate limiting and analytics.
