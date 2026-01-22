# Shared Services

## Purpose

Provide common utilities and data-access primitives shared by Gatekeeper and
Notary (e.g., token store, metrics, logging).

## Current implementation

- `veritas_shared` exposes a build-id helper.

## Placeholders / incomplete

- No shared data access layer. Token store is still implemented in the
  Gatekeeper service (not yet factored into shared code).

## Aspirational

- Shared DB access, token store adapters, and metrics/logging utilities.
