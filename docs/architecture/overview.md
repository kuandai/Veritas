# Architecture Overview

This document summarizes the high-level architecture and boundaries of the
Veritas system. It is intentionally concise; component-specific details live in
`docs/components/`.

## System boundaries

- **Client library (`libveritas`)**: used by C++ applications to obtain and
  manage identity material and security context.
- **Gatekeeper service**: performs authentication and issues refresh tokens.
- **Notary service**: consumes the shared token store for validation and
  related flows.
- **Shared services**: common data access, token store adapters, and utilities.
- **Protocol layer**: gRPC/Protobuf interfaces under `protocol/`.

## Data flow (conceptual)

1. Client uses `libveritas` to authenticate through Gatekeeper.
2. Gatekeeper issues refresh tokens and persists them to a shared store.
3. Notary (and other services) validate tokens via shared access.

## Status note

This overview describes the intended boundaries. Implementation status and
placeholders are tracked in `docs/status/current-state.md`.
