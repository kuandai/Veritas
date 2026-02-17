#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_TYPE:=Debug}"
: "${BUILD_DIR:=${ROOT_DIR}/build}"

export CONAN_HOME

if [[ -z "${VERITAS_REDIS_TLS_URI:-}" ]]; then
  echo "VERITAS_REDIS_TLS_URI is not set."
  echo "Set it to a reachable rediss:// URI to exercise successful TLS connectivity."
fi

conan install "${ROOT_DIR}" -of "${BUILD_DIR}" -s build_type="${BUILD_TYPE}" --build=missing

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR}/conan_toolchain.cmake" \
  -DVERITAS_ENABLE_PROTO_TESTS=ON \
  -DVERITAS_ENABLE_REDIS_INTEGRATION_TESTS=ON

cmake --build "${BUILD_DIR}" --parallel --target veritas_gatekeeper_redis_integration_tests

ctest --test-dir "${BUILD_DIR}" \
  -R veritas_gatekeeper_redis_integration_tests \
  --output-on-failure
