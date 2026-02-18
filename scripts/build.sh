#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_TYPE:=Debug}"
: "${VERITAS_ENABLE_PROTO_TESTS:=OFF}"

export CONAN_HOME

mkdir -p "${ROOT_DIR}/build"

echo "Using CONAN_HOME=${CONAN_HOME}"

echo "Installing Conan dependencies (build_type=${BUILD_TYPE})"
conan install "${ROOT_DIR}" -of "${ROOT_DIR}/build" -s build_type="${BUILD_TYPE}" --build=missing

# Conan generates a root-level CMakeUserPresets.json that may keep stale includes for
# build directories that have since been deleted. Prune missing includes so IDE tooling
# (CMake Tools / clangd integrations) doesn't emit noisy errors.
"${ROOT_DIR}/scripts/clean_user_presets.sh"

echo "Configuring CMake (VERITAS_ENABLE_PROTO_TESTS=${VERITAS_ENABLE_PROTO_TESTS})"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/build" \
  -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/build/conan_toolchain.cmake" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DVERITAS_ENABLE_PROTO_TESTS="${VERITAS_ENABLE_PROTO_TESTS}"

echo "Building"
cmake --build "${ROOT_DIR}/build" --parallel
