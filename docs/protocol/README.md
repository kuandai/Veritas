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

Notary payload semantics (current implementation):
- `IssueCertificateRequest` and `RenewCertificateRequest` carry
  `refresh_token`, requested lifetime, and `idempotency_key`.
- `RevokeCertificateRequest` carries `refresh_token`, target certificate serial,
  revocation reason code, and actor context.
- Revocation reason codes currently accepted:
  - `TOKEN_REVOKED`
  - `KEY_COMPROMISE`
  - `CA_COMPROMISE`
  - `AFFILIATION_CHANGED`
  - `SUPERSEDED`
  - `CESSATION_OF_OPERATION`
  - `PRIVILEGE_WITHDRAWN`
  - `POLICY_VIOLATION`
- `GetCertificateStatusRequest` carries `certificate_serial` and
  `refresh_token` for authz + ownership checks.
- `GetCertificateStatusResponse.state` reports lifecycle state:
  `ACTIVE`, `REVOKED`, `EXPIRED`, or `UNKNOWN`.
- `NotaryErrorDetail` + `NotaryErrorCode` define service-level structured error
  semantics alongside gRPC status.

## Placeholders / incomplete

- `identity.proto` is explicitly a placeholder.
- Cross-service protocol version negotiation is not implemented.

## Aspirational

- Complete identity protocol and version-negotiated cross-service contracts.
