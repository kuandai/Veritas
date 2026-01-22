# libveritas (Client Library)

## Purpose

Provide C++ clients with a simple integration point for identity material,
token rotation callbacks, and a security context for transport layers (TLS/QUIC).

## Current implementation

- `IdentityManager` exists with callback registration.
- `get_quic_context()` returns a default/empty `SecurityContext`.

## Placeholders / incomplete

- No transport integration.
- No certificate rotation logic.
- Callbacks are stored but not invoked.
- `SecurityContext` holds only a raw `SSL_CTX*`.

## Aspirational

- Production identity lifecycle management and automated rotation.
- Safe, opinionated TLS/QUIC setup for clients.
