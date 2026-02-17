#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
: "${BUILD_DIR:=${ROOT_DIR}/build}"
: "${SMOKE_DIR:=/tmp/veritas_smoke}"
: "${BIND_ADDR:=127.0.0.1:50051}"
: "${SASL_SERVICE:=veritas_gatekeeper}"
: "${SASL_REALM:=veritas-test}"

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

require_binary() {
  local path=$1
  if [[ ! -x "${path}" ]]; then
    echo "Missing executable: ${path}" >&2
    exit 1
  fi
}

CYRUS_ROOT=$(find_cyrus_root || true)
if [[ -z "${CYRUS_ROOT}" ]]; then
  echo "Unable to find SRP-capable Cyrus SASL package in ${CONAN_HOME}." >&2
  exit 1
fi

GATEKEEPER_BIN="${BUILD_DIR}/services/gatekeeper/veritas_gatekeeper"
AUTH_DEMO_BIN="${BUILD_DIR}/tools/veritas_auth_demo"
require_binary "${GATEKEEPER_BIN}"
require_binary "${AUTH_DEMO_BIN}"

mkdir -p "${SMOKE_DIR}/sasl"
SASL_DBNAME="${SMOKE_DIR}/sasldb2"
SASL_PATH="${CYRUS_ROOT}/lib/sasl2"
SASL_CONF_PATH="${SMOKE_DIR}/sasl"
TLS_CERT="${SMOKE_DIR}/server.crt"
TLS_KEY="${SMOKE_DIR}/server.key"
GATEKEEPER_LOG="${SMOKE_DIR}/gatekeeper.log"
CLIENT_LOG="${SMOKE_DIR}/client.log"

cat >"${SASL_CONF_PATH}/veritas_gatekeeper.conf" <<'EOF'
pwcheck_method: auxprop
auxprop_plugin: sasldb
mech_list: SRP
srp_mda: SHA-1
EOF

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "${TLS_KEY}" \
  -out "${TLS_CERT}" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  >/dev/null 2>&1

export SASL_PATH
export SASL_PLUGIN_PATH="${SASL_PATH}"
export SASL_CONF_PATH
export SASL_DBNAME
export SASL_REALM
export LD_LIBRARY_PATH="${CYRUS_ROOT}/lib:${LD_LIBRARY_PATH:-}"

USERNAME="demo_user_${RANDOM}@${SASL_REALM}"
PASSWORD="demo_pass_${RANDOM}_${RANDOM}"

"${AUTH_DEMO_BIN}" \
  --provision \
  --username "${USERNAME}" \
  --password "${PASSWORD}" \
  --sasldb "${SASL_DBNAME}" \
  --sasl-service "${SASL_SERVICE}" \
  --sasl-realm "${SASL_REALM}" \
  >/dev/null

cleanup() {
  if [[ -n "${GATEKEEPER_PID:-}" ]] && kill -0 "${GATEKEEPER_PID}" 2>/dev/null; then
    kill "${GATEKEEPER_PID}" 2>/dev/null || true
    wait "${GATEKEEPER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

BIND_ADDR="${BIND_ADDR}" \
TLS_CERT="${TLS_CERT}" \
TLS_KEY="${TLS_KEY}" \
SASL_ENABLE=true \
SASL_SERVICE="${SASL_SERVICE}" \
SASL_MECH_LIST=SRP \
SASL_CONF_PATH="${SASL_CONF_PATH}" \
SASL_PLUGIN_PATH="${SASL_PLUGIN_PATH}" \
SASL_DBNAME="${SASL_DBNAME}" \
SASL_REALM="${SASL_REALM}" \
TOKEN_STORE_URI= \
"${GATEKEEPER_BIN}" >"${GATEKEEPER_LOG}" 2>&1 &
GATEKEEPER_PID=$!

HOST_PART="${BIND_ADDR%:*}"
PORT_PART="${BIND_ADDR##*:}"

for _ in $(seq 1 100); do
  if ! kill -0 "${GATEKEEPER_PID}" 2>/dev/null; then
    echo "Gatekeeper exited during startup." >&2
    cat "${GATEKEEPER_LOG}" >&2
    exit 1
  fi
  if (echo >"/dev/tcp/${HOST_PART}/${PORT_PART}") >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! (echo >"/dev/tcp/${HOST_PART}/${PORT_PART}") >/dev/null 2>&1; then
  echo "Gatekeeper did not become ready in time." >&2
  cat "${GATEKEEPER_LOG}" >&2
  exit 1
fi

"${AUTH_DEMO_BIN}" \
  --target "${BIND_ADDR}" \
  --username "${USERNAME}" \
  --password "${PASSWORD}" \
  --root-cert "${TLS_CERT}" \
  >"${CLIENT_LOG}" 2>&1

if ! grep -q "Authenticated user_uuid=" "${CLIENT_LOG}"; then
  echo "Auth demo did not report successful authentication." >&2
  cat "${CLIENT_LOG}" >&2
  exit 1
fi

echo "Smoke auth demo passed."
echo "Gatekeeper log: ${GATEKEEPER_LOG}"
echo "Client log: ${CLIENT_LOG}"
