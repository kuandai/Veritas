# Protocol

## Purpose

Define gRPC/Protobuf interfaces for services.

## Current definitions

- `protocol/gatekeeper.proto`: Gatekeeper gRPC service and messages.
- `protocol/identity.proto`: **placeholder** message.

Gatekeeper payload semantics (current implementation):
- `BeginAuthRequest.client_start` carries the SASL SRP client initial response.
- `BeginAuthResponse.server_public` carries the SASL SRP server challenge
  payload; `salt` is only populated for deterministic fake responses.
- `FinishAuthRequest.client_proof` and `FinishAuthResponse.server_proof` carry
  the SASL SRP proof/final payloads.
- `RevokeTokenRequest` revokes a refresh token and carries optional reason
  metadata.
- `GetTokenStatusResponse.state` reports token lifecycle status:
  `ACTIVE`, `REVOKED`, or `UNKNOWN`.

## Placeholders / incomplete

- `identity.proto` is explicitly a placeholder.
- No explicit protocol versioning or service-level error model.

## Aspirational

- Complete identity, token, and notary protocol definitions.
