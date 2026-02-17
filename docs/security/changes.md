# Security Deployment Notes

Deployment-impacting security behavior currently enforced in this repository.

## Gatekeeper service

- Runtime authentication bypass is disabled in production builds:
  `SASL_ENABLE=false` causes startup failure.
- TLS server mode is enforced with TLS 1.3-only gRPC server credentials.
- Redis token-store TLS is supported via `rediss://` with fail-closed
  certificate validation.
- Session IDs are consumed atomically on `FinishAuth` to prevent replay/race
  reuse.
- Structured auth logs escape untrusted fields to preserve single-line JSON
  integrity.
- Rate-limiter and auth metrics maps are cardinality-bounded.

## Client library (`libveritas`)

- Insecure transport (`allow_insecure=true`) is rejected in release builds.

## Test and CI gates

- SRP strict mode is available via `VERITAS_STRICT_SRP=ON ./scripts/test.sh`.
- Strict mode fails when SRP integration tests skip.
- SRP verification artifacts (plugin discovery and test logs) are emitted under
  `build/security-artifacts/srp-strict`.
- Redis TLS integration tests include fail-closed validation and optional
  external endpoint connectivity validation.

## Remaining operator responsibilities

- Provision and protect SASL verifier storage (`sasldb`/auxprop backend).
- Provide trusted Redis TLS CA material for `rediss://` deployment.
- Run optional external Redis TLS connectivity tests in an environment with a
  reachable TLS-enabled Redis endpoint.
