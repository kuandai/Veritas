# Protocol

## Purpose

Define gRPC/Protobuf interfaces for services.

## Current definitions

- `protocol/gatekeeper.proto`: Gatekeeper gRPC service and messages.
- `protocol/notary.proto`: Notary v1 gRPC contract:
  - `IssueCertificate`
  - `RenewCertificate`
  - `RevokeCertificate`
  - `GetCertificateStatus`
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

Notary payload semantics (contract freeze, implementation pending):
- `IssueCertificateRequest` and `RenewCertificateRequest` carry
  `refresh_token`, requested lifetime, and `idempotency_key`.
- `RevokeCertificateRequest` carries `refresh_token`, target certificate serial,
  revocation reason, and actor context.
- `GetCertificateStatusResponse.state` reports lifecycle state:
  `ACTIVE`, `REVOKED`, `EXPIRED`, or `UNKNOWN`.
- `NotaryErrorDetail` + `NotaryErrorCode` define service-level structured error
  semantics alongside gRPC status.

## Placeholders / incomplete

- `identity.proto` is explicitly a placeholder.
- `notary.proto` is a frozen contract only; no server-side behavior is
  implemented yet.
- Cross-service protocol version negotiation is not implemented.

## Aspirational

- Complete identity and notary runtime implementations behind the frozen
  protocol contracts.
