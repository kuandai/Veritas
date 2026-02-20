# Protocol Definitions

This directory contains Protobuf definitions for Veritas. CMake generates the
C++ sources during the build and places them under the build tree.

Current definitions:
- `gatekeeper.proto`: implemented Gatekeeper auth/token API.
- `notary.proto`: Sprint 1 frozen Notary v1 contract (`Issue`, `Renew`,
  `Revoke`, `GetStatus`) with explicit service-level error/status enums.
- `identity.proto`: placeholder.

## Build Notes

- Add new `.proto` files to `protocol/CMakeLists.txt`.
- Run Conan to install dependencies before configuring CMake.

Example:

```bash
conan install . -of build -s build_type=Debug
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build
```
