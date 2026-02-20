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
  - `notary_service.*`: mutating RPC handlers enforce authz and currently return
    `FAILED_PRECONDITION` after authz as issuance pipeline placeholder.
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
  fail-closed key-material validation hooks (path checks, PEM parse, key/cert
  match).
- Health/readiness baseline:
  - default gRPC health service is enabled during startup,
  - service serving status is set for `veritas.notary.v1.Notary`.
- Gatekeeper authz integration:
  - `NOTARY_GATEKEEPER_TARGET` is required.
  - secure mode requires `NOTARY_GATEKEEPER_CA_BUNDLE`.
  - `NOTARY_GATEKEEPER_ALLOW_INSECURE=true` allows insecure transport only when
    explicitly set.
- Mutating RPC authorization mapping:
  - token state `ACTIVE` -> continue to issuance placeholder,
  - token state `REVOKED` -> `PERMISSION_DENIED`,
  - token state `UNKNOWN` / `UNSPECIFIED` -> `UNAUTHENTICATED`,
  - Gatekeeper `UNAVAILABLE` -> `UNAVAILABLE` (fail closed),
  - other Gatekeeper RPC failures -> `UNAUTHENTICATED`.

## Placeholders / incomplete

- Issuance/renewal/revocation/status business logic remains incomplete.
- Signer `Issue(...)` path remains a placeholder and intentionally not
  implemented.
- No issuance persistence layer.

## Aspirational

- Full notary service implementation with shared token store integration.
