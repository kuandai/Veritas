# Notary Release Checklist

## Build and Dependency Gate

- [ ] `./scripts/bootstrap.sh`
- [ ] `./scripts/lock.sh` (lockfile refresh completed)
- [ ] `./scripts/build.sh`

## Test Gate

- [ ] `./scripts/test.sh`
- [ ] `VERITAS_STRICT_SRP=ON ./scripts/test.sh`
- [ ] `ctest --test-dir build --output-on-failure -R veritas_notary_tests`
- [ ] `./scripts/smoke_notary_lifecycle.sh`

## CI Gate

- [ ] `security-srp / strict-srp` passed
- [ ] `security-srp / revocation-integration` passed
- [ ] `security-srp / notary-lifecycle` passed
- [ ] `security-srp / tsan-nightly` passed for scheduled/dispatch runs

## Runtime Configuration Gate

- [ ] Notary TLS certificate/key are valid and match.
- [ ] Signer certificate/key are valid and match.
- [ ] Gatekeeper target and CA bundle are set for secure authz path.
- [ ] Store backend mode (`memory` or `redis`) is explicitly chosen.
- [ ] Redis URI is set when `NOTARY_STORE_BACKEND=redis`.

## Rollout / Rollback Gate

- [ ] Deployment owner assigned.
- [ ] Rollback binary and env bundle prepared.
- [ ] Post-deploy smoke command scheduled:
      `./scripts/smoke_notary_lifecycle.sh`
