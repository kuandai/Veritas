# Notary Runbook

## Scope

Operational steps for deploying and validating `veritas_notary`.

## Required Configuration

Set these environment variables before startup:

- `NOTARY_BIND_ADDR`
- `NOTARY_TLS_CERT`
- `NOTARY_TLS_KEY`
- `NOTARY_SIGNER_CERT`
- `NOTARY_SIGNER_KEY`
- `NOTARY_GATEKEEPER_TARGET`
- `NOTARY_GATEKEEPER_CA_BUNDLE` unless
  `NOTARY_GATEKEEPER_ALLOW_INSECURE=true`

Optional:

- `NOTARY_SIGNER_CHAIN`
- `NOTARY_TLS_REQUIRE_CLIENT_CERT=true` (requires `NOTARY_TLS_CA_BUNDLE`)
- `NOTARY_STORE_BACKEND=memory|redis` (default `memory`)
- `NOTARY_STORE_URI` (required when backend is `redis`)

## Deployment Procedure

1. Build artifacts:

```bash
./scripts/build.sh
```

2. Start Gatekeeper with a reachable `GetTokenStatus` endpoint.

3. Start Notary:

```bash
NOTARY_BIND_ADDR=0.0.0.0:50061 \
NOTARY_TLS_CERT=/path/notary.crt \
NOTARY_TLS_KEY=/path/notary.key \
NOTARY_SIGNER_CERT=/path/issuer.crt \
NOTARY_SIGNER_KEY=/path/issuer.key \
NOTARY_SIGNER_CHAIN=/path/intermediate-chain.pem \
NOTARY_GATEKEEPER_TARGET=127.0.0.1:50051 \
NOTARY_GATEKEEPER_CA_BUNDLE=/path/gatekeeper-ca.pem \
build/services/notary/veritas_notary
```

## Validation

1. Confirm process startup logs include successful TLS/signer configuration.
2. Run local lifecycle smoke validation:

```bash
./scripts/smoke_notary_lifecycle.sh
```

3. Run full test suite when validating a new build candidate:

```bash
ctest --test-dir build --output-on-failure
```

## Rollback

1. Stop current Notary process.
2. Revert to previous binary + previous env configuration bundle.
3. Restart Notary.
4. Re-run `./scripts/smoke_notary_lifecycle.sh` and targeted service checks.

## Known Limits

- Lifecycle smoke currently validates service behavior through the test harness;
  a dedicated external notary RPC demo client is not yet implemented.
