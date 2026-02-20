# Shared Services

## Purpose

Provide common utilities and data-access primitives shared by Gatekeeper and
Notary (e.g., token store, metrics, logging).

## Current implementation

- `veritas_shared` exposes a build-id helper.
- Shared issuance persistence interface is implemented in
  `services/shared/include/veritas/shared/issuance_store.h` with support for:
  - issuance record storage,
  - token-hash -> certificate serial linkage,
  - idempotency key registration/lookup,
  - revocation state updates.
- Backends:
  - thread-safe in-memory backend,
  - Redis backend (with fail-closed behavior when redis support is unavailable).
- Shared-layer tests cover idempotency semantics, revocation updates, and
  concurrency behavior.

## Placeholders / incomplete

- Notary service is not yet wired to consume the shared issuance store.
- Gatekeeper token store remains a service-local implementation.

## Aspirational

- Shared DB access, token store adapters, and metrics/logging utilities.
