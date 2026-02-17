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

## 5. Packaging

`scripts/package.sh` is currently a placeholder. Decide on a packaging target
(containers or installable tarballs) before wiring CI deployment.

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
