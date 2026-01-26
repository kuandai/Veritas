# Build Guide

This repository uses CMake + Conan (C++20). The Gatekeeper integration tests
require Cyrus SASL with SRP enabled; a custom Conan recipe is provided in
`conan/recipes/`.

For the smoothest local workflow, use the scripts under `scripts/`:

```bash
./scripts/bootstrap.sh
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

## 3. Run tests

To include gRPC/SASL integration tests:

```bash
cmake -S . -B build -DVERITAS_ENABLE_PROTO_TESTS=ON
cmake --build build
ctest --test-dir build -R veritas_gatekeeper_ --output-on-failure
```

## 4. SRP plugin runtime configuration

If the SRP plugin is built as a shared module, set `SASL_PLUGIN_PATH` to the
Conan package's `lib/sasl2` directory before running the Gatekeeper service or
integration tests.

## 5. Packaging

`scripts/package.sh` is currently a placeholder. Decide on a packaging target
(containers or installable tarballs) before wiring CI deployment.
