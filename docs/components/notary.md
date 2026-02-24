# Notary Service

## Purpose

Issue, renew, revoke, and report status for identity certificates based on
authenticated authorization context.

## Current implementation

- gRPC server skeleton is implemented in `services/notary/src`:
  - `config.*`: fail-closed env-based startup config parsing.
  - `server.*`: TLS 1.3 server bootstrap + optional mTLS policy.
  - `authorizer.*`: Gatekeeper token-status client and refresh-token
    authorization mapping.
  - `notary_service.*`:
    - `IssueCertificate` enforces request validation + authz, invokes signer,
      persists issuance/idempotency data, and returns leaf + chain material.
    - `RenewCertificate` enforces request validation + authz, overlap-window
      policy, signer renewal, and idempotent persistence semantics.
    - `RevokeCertificate` enforces request validation + authz + ownership and
      persists revocation reason/actor/timestamp metadata.
    - `GetCertificateStatus` returns active/revoked/expired/unknown lifecycle
      state from persisted issuance records.
  - `security_controls.*`:
    - fixed-window per-peer request rate limiting for issue/renew/revoke/status,
    - in-memory security event counters for future policy/lockout analytics.
  - `log_utils.*`: JSON-structured event logging for startup/RPC events.
  - `tls_utils.*`: startup TLS cert/key format and match validation.
- Sprint 1 contract freeze is defined in `protocol/notary.proto`:
  - `IssueCertificate`
  - `RenewCertificate`
  - `RevokeCertificate`
  - `GetCertificateStatus`
- Notary error/status enums are frozen in the proto contract for implementation
  consistency.
- PKI policy baseline is defined in `docs/architecture/notary-pki-policy.md`.
- Signer abstraction is present in `services/notary/src/signer.*` with
  fail-closed key-material validation hooks and OpenSSL issuance/renewal paths:
  - CSR parse/signature verification,
  - SAN/CN/key-policy checks,
  - bounded TTL enforcement,
  - leaf signing/renewal with key-usage/EKU extensions,
  - renewal from existing certificate identity material (subject + SAN + key),
  - chain payload passthrough from configured issuer chain file.
- Health/readiness baseline:
  - default gRPC health service is enabled during startup,
  - service serving status is set for `veritas.notary.v1.Notary`.
- Gatekeeper authz integration:
  - `NOTARY_GATEKEEPER_TARGET` is required.
  - secure mode requires `NOTARY_GATEKEEPER_CA_BUNDLE`.
  - `NOTARY_GATEKEEPER_ALLOW_INSECURE=true` allows insecure transport only when
    explicitly set.
- Mutating RPC authorization mapping:
  - token state `ACTIVE` -> continue to issue/renew policy path,
  - token state `REVOKED` -> `PERMISSION_DENIED`,
  - token state `UNKNOWN` / `UNSPECIFIED` -> `UNAUTHENTICATED`,
  - Gatekeeper `UNAVAILABLE` -> `UNAVAILABLE` (fail closed),
  - other Gatekeeper RPC failures -> `UNAUTHENTICATED`.
- Shared issuance persistence integration:
  - `NOTARY_STORE_BACKEND=memory|redis` (default: memory),
  - `NOTARY_STORE_URI` is required for Redis backend,
  - issuance records persist serial, cert payload, token hash linkage, and
    idempotency key mapping.
- Renewal policy baseline:
  - overlap window enforced before renewal (`15m` from expiry boundary),
  - active/non-revoked record required,
  - token-hash ownership match required,
  - idempotency replay on duplicate renewal key.
- Revocation/status behavior:
  - revoke requires `reason` and `actor`,
  - revoke `reason` must be one of:
    `TOKEN_REVOKED`, `KEY_COMPROMISE`, `CA_COMPROMISE`,
    `AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`,
    `PRIVILEGE_WITHDRAWN`, `POLICY_VIOLATION`,
  - repeated revoke returns deterministic already-revoked error,
  - status lookup requires `refresh_token` and validates authz + token
    ownership before returning state + validity window + revocation metadata.
- Abuse-control hardening:
  - mutating and status RPC paths enforce per-peer rate limits,
  - request-size bounds enforced on token/csr/serial/idempotency/reason/actor
    fields,
  - security counters track key events (`rate_limited`, `authz_failure`,
    `validation_failure`, `policy_denied`) for future lockout policy work.
- Operational/demo entrypoints:
  - lifecycle smoke command: `scripts/smoke_notary_lifecycle.sh`,
  - runbook: `docs/operations/notary-runbook.md`,
  - release checklist: `docs/operations/notary-release-checklist.md`.

## Placeholders / incomplete

- Rate-limit thresholds are code-level defaults (runtime tuning not yet wired).

## Aspirational

- Runtime-tunable abuse controls and exportable security metrics.
- Dedicated external notary RPC demo client for deployment smoke checks.
