# Notary Threat Model (Sprint 1)

## Scope

This document defines trust boundaries and attacker goals for the Notary track.
It is a contract for implementation and review, not proof of implementation.

## Components and Trust Boundaries

1. Client application (`libveritas` consumer):
- Untrusted runtime environment from the server perspective.
- Trusted only to the extent of presenting valid Gatekeeper-issued credentials.

2. Gatekeeper service:
- Authentication authority for user credentials and refresh-token lifecycle.
- Trusted by Notary as an authorization signal source, not as a signing authority.

3. Notary service:
- Certificate issuance policy enforcement point.
- Must validate authorization context before any signing action.
- Must not trust client-supplied identity claims without Gatekeeper-backed validation.

4. Signing key material:
- Highest-sensitivity trust boundary.
- Must be loaded through fail-closed startup checks.
- Must never be exposed in logs, API payloads, or analytics events.

5. Shared storage and transport:
- Storage is trusted for durability but not for identity claims on its own.
- Network is untrusted; transport security and request validation are mandatory.

## Primary Security Objectives

- Only authorized identities can issue/renew/revoke certificates.
- Certificate profiles are policy-constrained and deterministic.
- Revocation and status reflect authoritative lifecycle state.
- Abuse attempts are observable and rate-controlled.

## Attacker Goals and Abuse Cases

1. Token replay:
- Goal: reuse captured token material to mint certificates.
- Required controls: token validation, replay-safe idempotency, revocation checks.

2. Issuance spam / resource exhaustion:
- Goal: degrade service or bypass operational controls.
- Required controls: rate limits, bounded request sizes, bounded parsing cost.

3. Malformed CSR/request payload exploitation:
- Goal: trigger parser bugs, policy bypass, or crash conditions.
- Required controls: strict schema validation, reject-on-parse-failure, defensive limits.

4. Privilege escalation by forged identity metadata:
- Goal: request certs for identities not owned by caller.
- Required controls: identity must derive from trusted auth context, not client fields.

5. Revocation bypass:
- Goal: continue using revoked credentials through stale state or inconsistent checks.
- Required controls: authoritative status lookup and revocation propagation guarantees.

## Out of Scope (Sprint 1)

- HSM/KMS integration details.
- Cross-region disaster recovery policy.
- Final production SLO/SLA policy.

## Known Gaps at Sprint 1 Start

- Notary service logic is not implemented yet.
- Shared persistence model for issuance lifecycle is not implemented yet.
- Authorization integration with Gatekeeper is not implemented yet.

## Traceability to Sprint Plan

- Sprint 1 checklist items for trust boundaries and attacker goals map directly
  to this document.
- Protocol freeze items are tracked in `protocol/notary.proto` and
  `docs/protocol/README.md`.
