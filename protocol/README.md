# Protocol Definitions

This directory contains Protobuf definitions for Veritas. CMake generates the
C++ sources during the build and places them under the build tree.

Current definitions:
- `gatekeeper.proto`: implemented Gatekeeper auth/token API.
- `notary.proto`: Sprint 1 frozen Notary v1 contract (`Issue`, `Renew`,
  `Revoke`, `GetStatus`) with explicit service-level error/status enums.
- `identity.proto`: identity protocol negotiation contract (`ProtocolVersion`,
  `NegotiateRequest`, `NegotiateResponse`, `Identity.Negotiate`).

## Compatibility policy

- Wire compatibility version is carried as gRPC metadata:
  - request key: `x-veritas-protocol`
  - response key: `x-veritas-protocol-selected`
- Current server version:
  - major: `1`
  - minor: `0`
- Compatibility behavior:
  - unsupported major -> request is rejected (`FAILED_PRECONDITION`),
  - malformed/missing version metadata -> request is rejected
    (`INVALID_ARGUMENT`),
  - higher compatible minor -> accepted with downgrade to the server-supported
    minor, echoed via `x-veritas-protocol-selected`.

## Build Notes

- Add new `.proto` files to `protocol/CMakeLists.txt`.
- Run Conan to install dependencies before configuring CMake.

Example:

```bash
conan install . -of build -s build_type=Debug
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build
```
