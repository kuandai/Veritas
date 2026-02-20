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

## Placeholders / incomplete

- No notary logic implemented.
- No signer implementation or key loading.
- No Gatekeeper authorization integration.
- No issuance persistence layer.

## Aspirational

- Full notary service implementation with shared token store integration.
