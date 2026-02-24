# Build Guide

This repository uses CMake + Conan (C++20). The Gatekeeper integration tests
require Cyrus SASL with SRP enabled; a custom Conan recipe is provided in
`conan/recipes/`.
The recipe also applies a small SRP `sasl_setpass` fix to avoid a segfault
when provisioning users via sasldb.

For the smoothest local workflow, use the scripts under `scripts/`:

```bash
./scripts/bootstrap.sh
./scripts/lock.sh
./scripts/build.sh
./scripts/test.sh
```

## 1. Export the SRP-enabled Cyrus SASL recipe

`scripts/bootstrap.sh` will export the recipe and ensure a Conan profile
exists. It defaults `CONAN_HOME` to `.conan/` in the repo. To export manually:

```bash
conan export conan/recipes/cyrus-sasl/2.1.28 --version 2.1.28
```

## 2. Configure dependencies and build

```bash
conan install . -of build -s build_type=Debug --build=missing
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build
```

`conanfile.txt` enables Redis TLS-capable dependencies by default:
`redis-plus-plus/*:with_tls=True` and `hiredis/*:with_ssl=True`.

## 3. Run tests

To include gRPC/SASL integration tests:

```bash
cmake -S . -B build -DVERITAS_ENABLE_PROTO_TESTS=ON
cmake --build build
ctest --test-dir build -R veritas_gatekeeper_ --output-on-failure
```

## 4. SRP plugin runtime configuration

If the SRP plugin is built as a shared module, set `SASL_PLUGIN_PATH` to the
Conan package's `lib/sasl2` directory before running the Gatekeeper service.
For client-side SASL (including libveritas tests/demos), set `SASL_PATH` to
the same directory; Cyrus SASL clients read `SASL_PATH` for plugin discovery.
Set `SASL_REALM` when using sasldb-backed SRP so the client authid is
realm-qualified (`user@realm`), matching the stored verifier.

`SASL_CONF_PATH` should point to a directory containing
`veritas_gatekeeper.conf` when using a custom SASL config (not a direct
file path).

Provision SASL SRP users reproducibly with:

```bash
./scripts/provision_sasl_user.sh \
  --username demo_user \
  --password demo_password \
  --sasldb /tmp/veritas_sasldb2 \
  --sasl-realm veritas-test
```

## 5. Packaging

Create reproducible release tarballs from an existing build:

```bash
./scripts/package.sh
```

By default this packages artifacts from `build/` into `dist/` and creates:

- `dist/veritas-<version>-<platform>.tar.gz`
- `dist/veritas-<version>-<platform>.tar.gz.sha256`

Archive contents include:

- `bin/veritas_gatekeeper`
- `bin/veritas_notary`
- `lib/libveritas.a`
- `lib/libveritas_protocol.a`
- `include/` public libveritas headers
- `protocol/` protobuf source contracts
- `metadata/manifest.txt`
- `metadata/SHA256SUMS`

To verify package integrity:

```bash
./scripts/verify_package.sh
```

`scripts/package.sh` also runs verification automatically unless
`VERIFY_PACKAGE=false` is set.

CI publication policy:

- Workflow job `package-artifacts` builds release binaries and runs package +
  verification.
- Artifacts are uploaded via GitHub Actions as `veritas-package-<sha>`.
- Artifact retention is 14 days.

## 6. Lockfile generation

`scripts/lock.sh` will generate `conan.lock`. It requires access to the Conan
remotes configured for dependency resolution.

## 7. Redis TLS configuration

When enabling Redis persistence (`TOKEN_STORE_URI`), Gatekeeper accepts:

- `redis://[:password@]host:port/db`
- `rediss://[user[:password]@]host:port/db?...`

For `rediss://`:

- `verify_peer=true` (default) requires `cacert` or `cacertdir`.
- Client-auth requires both `cert` and `key`.
- Optional `sni` can override TLS SNI host.

## 8. Strict SRP verification

For security/release validation, run SRP tests in strict mode:

```bash
VERITAS_ENABLE_PROTO_TESTS=ON ./scripts/build.sh
VERITAS_STRICT_SRP=ON ./scripts/test.sh
```

This mode fails if SRP tests skip, and writes verification artifacts to:

- `build/security-artifacts/srp-strict/environment.txt`
- `build/security-artifacts/srp-strict/pluginviewer-server.txt`
- `build/security-artifacts/srp-strict/pluginviewer-client.txt`

## 9. Redis TLS integration test path

Use `scripts/test_redis_tls_integration.sh` to run the Redis TLS integration
target. The script always validates fail-closed behavior for invalid `rediss://`
configuration and can also validate real TLS connectivity.

```bash
VERITAS_REDIS_TLS_URI='rediss://user:pass@redis.example:6380/0?cacert=/path/ca.pem' \
  ./scripts/test_redis_tls_integration.sh
```

If `VERITAS_REDIS_TLS_URI` is unset, the external-connectivity test is skipped.

## 10. Gatekeeper + Demo Smoke Test

Run an end-to-end local smoke test (provision user, start Gatekeeper with TLS,
authenticate via `veritas_auth_demo`):

```bash
./scripts/smoke_auth_demo.sh
```

The script writes logs under `/tmp/veritas_smoke` by default.

## 11. Notary Lifecycle Smoke Test

Run the notary lifecycle smoke path (`issue -> renew -> revoke -> status`)
through the deterministic test harness:

```bash
./scripts/smoke_notary_lifecycle.sh
```

## 12. Sanitizer Notes

TSAN coverage is wired in CI as the `tsan-nightly` job in
`.github/workflows/security-srp.yml` (nightly schedule + manual dispatch).
The TSAN lane applies `tests/tsan-grpc.supp` to suppress known third-party
gRPC EventEngine race reports so project-owned races remain actionable.
For local ASAN/UBSAN checks:

```bash
cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

For Gatekeeper auth/session sanitizer runs, use
`ASAN_OPTIONS=detect_leaks=0` to ignore known Cyrus SRP leak reports in
third-party code paths.

## 13. Release Transport Gate Checks

To validate release-mode transport policy gates:

```bash
conan install . -of build_release -s build_type=Release --build=missing
cmake -S . -B build_release \
  -DCMAKE_TOOLCHAIN_FILE=build_release/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DVERITAS_ENABLE_PROTO_TESTS=ON
cmake --build build_release --parallel \
  --target veritas_gatekeeper_tests veritas_libveritas_tests
./build_release/tests/veritas_gatekeeper_tests \
  --gtest_filter=ConfigTest.LoadConfigRejectsSaslDisabled
./build_release/tests/veritas_libveritas_tests \
  --gtest_filter=GatekeeperClientTest.InsecureTransportPolicyMatchesBuildType
```
