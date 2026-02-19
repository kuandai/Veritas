#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${BUILD_DIR:=${ROOT_DIR}/build}"

AUTH_DEMO_TEST_BIN="${BUILD_DIR}/tests/veritas_libveritas_tests"

if [[ ! -x "${AUTH_DEMO_TEST_BIN}" ]]; then
  echo "Missing test binary: ${AUTH_DEMO_TEST_BIN}" >&2
  echo "Build the project first (e.g. ./scripts/build.sh)." >&2
  exit 1
fi

echo "==> Login smoke demo"
"${ROOT_DIR}/scripts/smoke_auth_demo.sh"

echo "==> Persisted reload + revocation lock demo"
"${AUTH_DEMO_TEST_BIN}" \
  --gtest_filter=IdentityManagerIntegrationTest.AuthenticatePersistsIdentity:IdentityManagerIntegrationTest.RevocationTransitionsToLocked \
  --gtest_brief=1

echo "Identity lifecycle demo passed."
