# Notary Service

## Purpose

Issue, renew, revoke, and report status for identity certificates based on
authenticated authorization context.

## Current implementation

- gRPC server skeleton is implemented in `services/notary/src`:
  - `config.*`: fail-closed env-based startup config parsing.
  - `server.*`: TLS 1.3 server bootstrap + optional mTLS policy.
  - `notary_service.*`: Notary RPC handlers currently return
    `UNIMPLEMENTED` with structured logging.
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

## Placeholders / incomplete

- Business logic for issuance/renewal/revocation/status is not implemented.
- Signer `Issue(...)` path remains a placeholder and intentionally not
  implemented.
- No Gatekeeper authorization integration.
- No issuance persistence layer.

## Aspirational

- Full notary service implementation with shared token store integration.
