# Notary PKI Policy Baseline (Sprint 2)

## Scope

This policy defines the Notary certificate-profile contract and lifecycle
semantics. It is normative for future implementation but does not imply that
all behaviors are implemented in code today.

## Certificate Profile

### Subject Mapping

- Issued leaf certificates map identity from authenticated authorization
  context; client-supplied identity fields are policy inputs, not authority.
- Subject CN is treated as display-compatible metadata and must not be relied on
  as the sole authorization identity.

### SAN/CN Rules

- SAN is authoritative for service identity.
- CN, when present, must be consistent with SAN policy and is overrideable by
  policy.
- Unsupported SAN types are rejected.

### Key Usage / EKU Baseline

- Leaf certificates must include key usage and EKU compatible with client auth
  and service-to-service auth as policy permits.
- CA key usage is never returned to clients in leaf material.

### Validity Window Baseline

- Issued certificates have bounded lifetimes set by policy maximums, independent
  of requested TTL.
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

### Revocation Reason Taxonomy (initial)

- `KEY_COMPROMISE`
- `CREDENTIAL_COMPROMISE`
- `POLICY_VIOLATION`
- `CESSATION_OF_OPERATION`
- `ADMINISTRATIVE_ACTION`
- `TOKEN_REVOKED`
- `UNSPECIFIED`

## Error Semantics Contract

- Service-level classification uses `NotaryErrorCode` from
  `protocol/notary.proto`.
- gRPC status remains transport-level status; payload-level `NotaryErrorDetail`
  carries stable semantic category.

## Implementation Status Notes

- This policy is documented and frozen as Sprint 2 baseline.
- Final issuance behavior remains pending Notary runtime implementation.
