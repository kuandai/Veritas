# Gatekeeper Service

## Purpose

Authenticate clients and issue refresh tokens via a gRPC interface.

## Current implementation

- gRPC server starts with TLS key/cert from env config (TLS 1.3 only).
- TLS credentials are validated at startup (key matches leaf cert, validity
  window, optional chain verification when a CA bundle is provided).
- Optional mTLS enforcement via CA bundle + client cert requirement.
- `BeginAuth` / `FinishAuth` handlers exist.
- `RevokeToken` / `GetTokenStatus` handlers exist.
- Per-IP rate limiting (5/minute) with oldest-bucket eviction when the
  in-memory key cap is reached (default: 10,000 keys).
- Structured logging to stdout (`timestamp`, `ip`, `action`, `status`,
  optional `user_uuid`) with JSON escaping for log field values.
- In-memory auth analytics counters (success/failure per IP and per UUID) with
  bounded key cardinality and oldest-entry eviction (default: 10,000 keys per
  map).
- SASL SRP-6a via Cyrus SASL:
  - `BeginAuth` seeds a SASL session and returns the SASL server challenge in
    `server_public` (opaque payload).
  - `BeginAuthRequest.client_start` carries the SASL client initial response
    and is required.
  - `BeginAuth` responses always include a deterministic per-username fake salt
    to reduce username enumeration signals.
  - `BeginAuth` enforces a minimum response-duration budget (default: 8ms)
    before returning.
  - Unknown users receive a fake challenge and are marked for rejection during
    `FinishAuth`; fake challenge size is normalized to the observed SASL
    challenge-size baseline (default seed: 512 bytes).
    Clients still use the SASL challenge payload to compute proofs.
  - `FinishAuth` validates the client proof via SASL and returns the SASL
    server final payload in `server_proof` (accepting SRP's final
    `SASL_CONTINUE` as success when a server proof is present).
  - Session ids stored in a TTL cache and consumed atomically on `FinishAuth`.
  - Refresh token issuance + SHA-256 hashing stored in Redis when
    `TOKEN_STORE_URI` is set (in-memory fallback otherwise).
  - Revocation/tombstone behavior:
    - `RevokeToken` marks token status revoked with reason metadata.
    - revoked token hashes are tombstoned for 24 hours.
    - replay attempts using tombstoned token hashes are rejected.
    - `GetTokenStatus` returns `ACTIVE`, `REVOKED`, or `UNKNOWN`.
  - Redis URI parsing supports `redis://` and `rediss://`.
    `rediss://` enforces fail-closed TLS config validation:
    `verify_peer=true` (default) requires `cacert` or `cacertdir` query
    parameters; client cert auth requires both `cert` and `key`.

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
`SASL_ENABLE=false` is rejected at startup in this build. Test-only mock auth
is available only when Gatekeeper is compiled with
`VERITAS_ENABLE_TEST_AUTH_BYPASS` and explicitly enabled through
`SaslServerOptions`.
Note: client-side SASL (libveritas tests/demos) uses `SASL_PATH` for plugin
discovery; set it to the same `lib/sasl2` directory when running clients.
For SRP, set `SASL_REALM` and ensure the client authid is realm-qualified
(`user@realm`); the client library now appends `@<realm>` automatically when
`SASL_REALM` is set.
Use `scripts/provision_sasl_user.sh` for reproducible SRP verifier
provisioning into sasldb during local/staging setup.

Redis token-store URIs:

- `redis://[:password@]host:port/db`
- `rediss://[user[:password]@]host:port/db?cacert=/path/ca.pem`
- Optional `rediss://` query parameters: `cacertdir`, `cert`, `key`, `sni`,
  `verify_peer` (`true`/`false`, default `true`).

## Placeholders / incomplete

- SASL SRP handshake depends on sasldb/auxprop backend configuration in the
  target environment.
  Use the repo's custom Cyrus SASL recipe when provisioning users via
  `saslpasswd2` to avoid the upstream SRP `sasl_setpass` crash.
- Rate-limiter and analytics key caps use code-level defaults; runtime tuning
  via config/env is not implemented.
- `BeginAuth` still returns mechanism-generated challenge bytes for real users;
  strict constant-size envelope encoding for all responses is not implemented.
- Redis token store adapter exists; persistence is optional via
  `TOKEN_STORE_URI` (in-memory fallback otherwise).
- Tombstone retention is fixed at 24 hours (no runtime tuning yet).
- Redis TLS requires a `redis-plus-plus` build with TLS enabled; Gatekeeper
  fails closed when `rediss://` is configured without TLS-capable client libs.
- gRPC error mapping is limited to current SASL status handling.
- Unit tests cover fake salt, token hashing, rate limiting, config validation,
  TLS credential validation, token store behavior (including tombstones/replay
  rejection), and session cache handling.
- Integration tests cover SRP handshake happy path + invalid proof + revocation
  status paths (skipped
  if SRP is unavailable in the SASL build).

## Aspirational

- Streamlined SRP verifier provisioning and server-side rotation policy.
- Redis-backed token store shared with Notary.
- Exportable metrics for rate limiting and analytics.
