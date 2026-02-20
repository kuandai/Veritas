# Notary Service

## Purpose

Issue, renew, revoke, and report status for identity certificates based on
authenticated authorization context.

## Current implementation

- Minimal CLI that prints a shared build id.
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

## Placeholders / incomplete

- No notary logic implemented.
- Signer `Issue(...)` path is a placeholder and intentionally not implemented.
- No Gatekeeper authorization integration.
- No issuance persistence layer.

## Aspirational

- Full notary service implementation with shared token store integration.
