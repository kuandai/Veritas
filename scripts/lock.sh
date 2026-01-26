#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_TYPE:=Debug}"

export CONAN_HOME

echo "Generating conan.lock (build_type=${BUILD_TYPE})"
conan lock create "${ROOT_DIR}/conanfile.txt" \
  -s build_type="${BUILD_TYPE}" \
  --lockfile-out "${ROOT_DIR}/conan.lock"
