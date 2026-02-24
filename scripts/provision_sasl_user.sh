#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_DIR:=${ROOT_DIR}/build}"
: "${SASL_SERVICE:=veritas_gatekeeper}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/provision_sasl_user.sh --username USER --password PASS --sasldb PATH [options]

Options:
  --username USER         Username to provision (required)
  --password PASS         Password/verifier source secret (required)
  --sasldb PATH           sasldb2 file path (required)
  --sasl-service NAME     SASL service name (default: veritas_gatekeeper)
  --sasl-realm REALM      Optional realm; username is qualified as user@realm
                           if realm is set and username has no '@'
  --build-dir PATH        Build directory containing veritas_auth_demo
  --help                  Show this help
EOF
}

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

qualify_user() {
  local user=$1
  local realm=$2
  if [[ -n "${realm}" && "${user}" != *@* ]]; then
    printf '%s@%s\n' "${user}" "${realm}"
    return 0
  fi
  printf '%s\n' "${user}"
}

USERNAME=""
PASSWORD=""
SASL_DBNAME=""
SASL_REALM="${SASL_REALM:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --username)
      USERNAME=${2:-}
      shift 2
      ;;
    --password)
      PASSWORD=${2:-}
      shift 2
      ;;
    --sasldb)
      SASL_DBNAME=${2:-}
      shift 2
      ;;
    --sasl-service)
      SASL_SERVICE=${2:-}
      shift 2
      ;;
    --sasl-realm)
      SASL_REALM=${2:-}
      shift 2
      ;;
    --build-dir)
      BUILD_DIR=${2:-}
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${USERNAME}" || -z "${PASSWORD}" || -z "${SASL_DBNAME}" ]]; then
  echo "Missing required arguments." >&2
  usage >&2
  exit 1
fi

CYRUS_ROOT=$(find_cyrus_root || true)
if [[ -z "${CYRUS_ROOT}" ]]; then
  echo "Unable to find SRP-capable Cyrus SASL package in ${CONAN_HOME}." >&2
  exit 1
fi

AUTH_DEMO_BIN="${BUILD_DIR}/tools/veritas_auth_demo"
if [[ ! -x "${AUTH_DEMO_BIN}" ]]; then
  echo "Missing executable: ${AUTH_DEMO_BIN}" >&2
  echo "Build first: ./scripts/build.sh" >&2
  exit 1
fi

export SASL_PATH="${CYRUS_ROOT}/lib/sasl2"
export SASL_PLUGIN_PATH="${SASL_PATH}"
export SASL_DBNAME
if [[ -n "${SASL_REALM}" ]]; then
  export SASL_REALM
fi
export LD_LIBRARY_PATH="${CYRUS_ROOT}/lib:${LD_LIBRARY_PATH:-}"

QUALIFIED_USER=$(qualify_user "${USERNAME}" "${SASL_REALM}")

cmd=(
  "${AUTH_DEMO_BIN}"
  --provision
  --username "${QUALIFIED_USER}"
  --password "${PASSWORD}"
  --sasldb "${SASL_DBNAME}"
  --sasl-service "${SASL_SERVICE}"
)
if [[ -n "${SASL_REALM}" ]]; then
  cmd+=(--sasl-realm "${SASL_REALM}")
fi
"${cmd[@]}" >/dev/null

echo "Provisioned SASL user ${QUALIFIED_USER}."
echo "sasldb: ${SASL_DBNAME}"
