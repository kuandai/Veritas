#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
export CONAN_HOME

mkdir -p "${CONAN_HOME}"

echo "Using CONAN_HOME=${CONAN_HOME}"

conan profile detect --force

conan export "${ROOT_DIR}/conan/recipes/cyrus-sasl/2.1.28" --version 2.1.28

echo "Bootstrap complete."
