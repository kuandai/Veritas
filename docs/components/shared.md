# Shared Services

## Purpose

Provide common data-access and utility primitives used by backend services.

## Current implementation

- `veritas_shared` provides shared utility code and storage abstractions.
- Shared issuance persistence (`services/shared/include/veritas/shared/issuance_store.h`)
  implements:
  - certificate issuance record persistence,
  - token-hash to certificate-serial linkage,
  - idempotency registration/lookup,
  - revocation metadata updates.
- Shared refresh-token persistence (`services/shared/include/veritas/shared/token_store.h`)
  implements:
  - token put/get/status/revoke/rotate/revoke-user operations,
  - bounded grace-window rotation semantics for per-user token swaps,
  - replay rejection with revocation tombstones,
  - Redis URI parsing for `redis://` and `rediss://`,
  - fail-closed Redis TLS option validation.
- Backends:
  - thread-safe in-memory implementations,
  - Redis implementations (with explicit unavailable errors when Redis support
    is not compiled in).
- Gatekeeper now consumes the shared token-store API through its compatibility
  header (`services/gatekeeper/src/token_store.h`).
- Shared-layer tests cover idempotency, revocation semantics, grace-window
  rotation expiry, replay rejection, and concurrency behavior.

## Placeholders / incomplete

- Shared metrics/logging primitives are still service-local.

## Aspirational

- Unified DB topology and migrations shared across services.
