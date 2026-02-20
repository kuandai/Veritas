#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${BUILD_DIR:=${ROOT_DIR}/build}"

NOTARY_TEST_BIN="${BUILD_DIR}/tests/veritas_notary_tests"
SMOKE_FILTER="NotaryServiceTest.LifecycleIssueRenewRevokeStatus"

if [[ ! -x "${NOTARY_TEST_BIN}" ]]; then
  echo "Missing test binary: ${NOTARY_TEST_BIN}" >&2
  echo "Build the project first (e.g. ./scripts/build.sh)." >&2
  exit 1
fi

echo "==> Notary lifecycle smoke: issue -> renew -> revoke -> status"
"${NOTARY_TEST_BIN}" --gtest_filter="${SMOKE_FILTER}" --gtest_brief=1

echo "Notary lifecycle smoke test passed."
