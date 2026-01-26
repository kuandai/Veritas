# Build Guide

This repository uses CMake + Conan (C++20). The Gatekeeper integration tests
require Cyrus SASL with SRP enabled; a custom Conan recipe is provided in
`conan/recipes/`.

## 1. Export the SRP-enabled Cyrus SASL recipe

```bash
conan export conan/recipes/cyrus-sasl/2.1.28 --version 2.1.28
```

If your default Conan home is not writable, set `CONAN_HOME` to a writable
location and use that consistently:

```bash
CONAN_HOME=/tmp/conan-home conan export conan/recipes/cyrus-sasl/2.1.28 --version 2.1.28
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
