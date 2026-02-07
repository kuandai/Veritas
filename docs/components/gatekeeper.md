# Gatekeeper Service

## Purpose

Authenticate clients and issue refresh tokens via a gRPC interface.

## Current implementation

- gRPC server starts with TLS key/cert from env config (TLS 1.3 only).
- TLS credentials are validated at startup (key matches leaf cert, validity
  window, optional chain verification when a CA bundle is provided).
- Optional mTLS enforcement via CA bundle + client cert requirement.
- `BeginAuth` / `FinishAuth` handlers exist.
- Per-IP rate limiting (5/minute).
- Structured logging to stdout (`timestamp`, `ip`, `action`, `status`,
  optional `user_uuid`).
- In-memory auth analytics counters (success/failure per IP and per UUID).
- SASL SRP-6a via Cyrus SASL:
  - `BeginAuth` seeds a SASL session and returns the SASL server challenge in
    `server_public` (opaque payload).
  - `BeginAuthRequest.client_start` carries the SASL client initial response
    and is required when SASL is enabled.
  - Unknown users receive a deterministic fake salt plus a fake challenge to
    reduce enumeration signals.
  - For real users the `salt` field is empty; clients must use the SASL
    challenge payload to compute proofs.
  - `FinishAuth` validates the client proof via SASL and returns the SASL
    server final payload in `server_proof` (accepting SRP's final
    `SASL_CONTINUE` as success when a server proof is present).
  - Session ids stored in a TTL cache.
  - Refresh token issuance + SHA-256 hashing stored in Redis when
    `TOKEN_STORE_URI` is set (in-memory fallback otherwise).

## Configuration notes

TLS behavior is controlled by environment variables:

- `TLS_CERT` (PEM chain: leaf + intermediates)
- `TLS_KEY` (PEM private key)
- `TLS_CA_BUNDLE` (optional CA bundle PEM for chain verification and mTLS)
- `TLS_REQUIRE_CLIENT_CERT` (default: false)

SASL behavior is controlled by environment variables:

- `SASL_ENABLE` (default: true)
- `SASL_SERVICE` (default: `veritas_gatekeeper`)
- `SASL_MECH_LIST` (default: `SRP`)
- `SASL_CONF_PATH` (optional)
- `SASL_PLUGIN_PATH` (optional)
- `SASL_DBNAME` (optional, sasldb path)
- `SASL_REALM` (optional)
- `SASL_ENABLE=false` forces a mock handshake (intended for tests only).
Note: client-side SASL (libveritas tests/demos) uses `SASL_PATH` for plugin
discovery; set it to the same `lib/sasl2` directory when running clients.
For SRP, set `SASL_REALM` and ensure the client authid is realm-qualified
(`user@realm`); the client library now appends `@<realm>` automatically when
`SASL_REALM` is set.

## Placeholders / incomplete

- SASL SRP handshake depends on external SASL configuration (sasldb/auxprop);
  verifier provisioning is not automated.
  Use the repo's custom Cyrus SASL recipe when provisioning users via
  `saslpasswd2` to avoid the upstream SRP `sasl_setpass` crash.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Redis TLS (`rediss://`) is not supported yet.
- gRPC error mapping is limited to current SASL status handling.
- Unit tests cover fake salt, token hashing, rate limiting, config validation,
  TLS credential validation, token store behavior, and session cache handling.
- Integration tests cover SRP handshake happy path + invalid proof (skipped
  if SRP is unavailable in the SASL build).

## Aspirational

- Streamlined SRP verifier provisioning and server-side rotation policy.
- Redis-backed token store shared with Notary.
- Exportable metrics for rate limiting and analytics.
