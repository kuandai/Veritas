# Veritas

Veritas is a C++ identity/authentication project with three primary parts:

- `libveritas`: client library used by applications.
- `gatekeeper`: authentication service.
- `notary`: certificate issuance service (planned; currently minimal).

## Architecture (high-level)

At a high level:

1. A client application uses `libveritas` to authenticate with Gatekeeper.
2. Gatekeeper verifies identity and issues auth material/tokens.
3. Notary is intended to issue certificates based on trusted auth state.

The repo currently focuses on the client auth path (`libveritas` + Gatekeeper),
with Notary present as an evolving backend component.

## Build prerequisites

- Linux
- C++20 compiler
- CMake
- Python 3
- Conan 2

## Build (recommended scripts)

From the repository root:

```bash
./scripts/bootstrap.sh
./scripts/lock.sh
./scripts/build.sh
./scripts/test.sh
```

## Build (manual)

```bash
conan install . -of build -s build_type=Debug --build=missing
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```
