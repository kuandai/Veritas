# Notary PKI Policy Baseline (Sprint 2)

## Scope

This policy defines the Notary certificate-profile contract and lifecycle
semantics as implemented in the current codebase.

## Certificate Profile

### Subject Mapping

- Issued leaf certificates map identity from authenticated authorization
  context; client-supplied identity fields are policy inputs, not authority.
- Subject CN is treated as display-compatible metadata and must not be relied on
  as the sole authorization identity.

### SAN/CN Rules

- SAN is authoritative for service identity.
- CN is set from authoritative principal identity from Gatekeeper authz
  context, not from CSR subject identity claims.
- Unsupported SAN types are rejected.

### Key Usage / EKU Baseline

- Leaf certificates must include key usage and EKU compatible with client auth
  and service-to-service auth as policy permits.
- CA key usage is never returned to clients in leaf material.
- Signer hash policy is explicit and fail-closed:
  - `NOTARY_SIGNER_HASH_ALGORITHM=sha256` (currently the only accepted value).

### Validity Window Baseline

- Issued certificates have bounded lifetimes set by policy maximums, independent
  of requested TTL.
- `not_before` is backdated by policy skew to tolerate clock drift:
  - `NOTARY_SIGNER_NOT_BEFORE_SKEW_SECONDS` default `900` (15 minutes),
  - accepted bounds `1..3600` seconds.
- Renewal requests are clamped to policy limits.
- Overlap window behavior is deterministic and policy-controlled.

## Chain Return Policy

- Notary responses return:
  - leaf certificate,
  - intermediate chain.
- Root certificate is never returned in issuance/renewal response payloads.

## Revocation Semantics

- Revocation is authoritative and terminal for the targeted serial in current
  lifecycle state.
- Re-revocation returns deterministic status (`ALREADY_REVOKED` equivalent).
- Revocation reasons are taxonomy-driven for audit/analytics consistency.

### Revocation Reason Taxonomy (current)

- `KEY_COMPROMISE`
- `CA_COMPROMISE`
- `AFFILIATION_CHANGED`
- `SUPERSEDED`
- `CESSATION_OF_OPERATION`
- `PRIVILEGE_WITHDRAWN`
- `POLICY_VIOLATION`
- `TOKEN_REVOKED`

## Error Semantics Contract

- Service-level classification uses `NotaryErrorCode` from
  `protocol/notary.proto`.
- gRPC status remains transport-level status; payload-level `NotaryErrorDetail`
  carries stable semantic category.

## Implementation Status Notes

- Policy controls above are implemented in `services/notary/src/signer.*` and
  Notary runtime config parsing.
