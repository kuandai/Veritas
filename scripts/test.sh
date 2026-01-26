#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${CTEST_ARGS:=}"

export CONAN_HOME

echo "Running tests"
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure ${CTEST_ARGS}
