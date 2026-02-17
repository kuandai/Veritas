#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_DIR:=${ROOT_DIR}/build}"
: "${ARTIFACT_DIR:=${BUILD_DIR}/security-artifacts/srp-strict}"

mkdir -p "${ARTIFACT_DIR}"

find_cyrus_root() {
  local pluginviewer
  while IFS= read -r pluginviewer; do
    local root
    root=$(dirname "$(dirname "${pluginviewer}")")
    if compgen -G "${root}/lib/sasl2/libsrp*" >/dev/null; then
      echo "${root}"
      return 0
    fi
  done < <(find "${CONAN_HOME}/p" -path '*/p/bin/pluginviewer' -type f | sort)
  return 1
}

CYRUS_ROOT=$(find_cyrus_root || true)
if [[ -z "${CYRUS_ROOT}" ]]; then
  echo "Failed to locate Cyrus SASL package with SRP plugin in ${CONAN_HOME}." >&2
  exit 1
fi

SASL_PATH="${CYRUS_ROOT}/lib/sasl2"
export SASL_PATH
export SASL_PLUGIN_PATH="${SASL_PATH}"
export LD_LIBRARY_PATH="${CYRUS_ROOT}/lib:${LD_LIBRARY_PATH:-}"

{
  echo "CONAN_HOME=${CONAN_HOME}"
  echo "CYRUS_ROOT=${CYRUS_ROOT}"
  echo "SASL_PATH=${SASL_PATH}"
} >"${ARTIFACT_DIR}/environment.txt"

ls -la "${SASL_PATH}" >"${ARTIFACT_DIR}/plugins.txt"

"${CYRUS_ROOT}/bin/pluginviewer" -s -p "${SASL_PATH}" \
  >"${ARTIFACT_DIR}/pluginviewer-server.txt" 2>&1
"${CYRUS_ROOT}/bin/pluginviewer" -c -p "${SASL_PATH}" \
  >"${ARTIFACT_DIR}/pluginviewer-client.txt" 2>&1

if ! grep -Eiq '(^|[^A-Za-z])srp([^A-Za-z]|$)' \
    "${ARTIFACT_DIR}/pluginviewer-server.txt"; then
  echo "SRP mechanism was not detected in pluginviewer server output." >&2
  exit 1
fi

run_and_require_no_skips() {
  local test_bin=$1
  local output_file=$2
  if [[ ! -x "${test_bin}" ]]; then
    echo "Missing expected test binary: ${test_bin}" >&2
    exit 1
  fi

  "${test_bin}" --gtest_brief=1 | tee "${output_file}"

  if grep -Eq '\[  SKIPPED \]|Skipped' "${output_file}"; then
    echo "Strict SRP run detected skipped tests in ${test_bin}." >&2
    exit 1
  fi
}

run_and_require_no_skips \
  "${BUILD_DIR}/tests/veritas_gatekeeper_integration_tests" \
  "${ARTIFACT_DIR}/veritas_gatekeeper_integration_tests.log"

run_and_require_no_skips \
  "${BUILD_DIR}/tests/veritas_libveritas_tests" \
  "${ARTIFACT_DIR}/veritas_libveritas_tests.log"

echo "Strict SRP verification completed with no skipped tests."
