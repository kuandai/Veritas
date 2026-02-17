#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${CTEST_ARGS:=}"
: "${VERITAS_STRICT_SRP:=OFF}"

export CONAN_HOME

if [[ "${VERITAS_STRICT_SRP}" == "ON" ]]; then
  echo "Running strict SRP tests"
  "${ROOT_DIR}/scripts/test_srp_strict.sh"
else
  echo "Running tests"
  ctest --test-dir "${ROOT_DIR}/build" --output-on-failure ${CTEST_ARGS}
fi
