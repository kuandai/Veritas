#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${REDIS_TLS_IMAGE:=redis:7.2-alpine}"
: "${REDIS_TLS_PORT:=6380}"
: "${BUILD_TYPE:=Debug}"
: "${BUILD_DIR:=${ROOT_DIR}/build_redis_tls}"
: "${KEEP_REDIS_TLS_ARTIFACTS:=0}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the Redis TLS validation lane" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate ephemeral Redis TLS certificates" >&2
  exit 1
fi

redis_password="${REDIS_TLS_PASSWORD:-$(openssl rand -hex 16)}"
container_name="veritas-redis-tls-$$"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/veritas-redis-tls.XXXXXX")"
tls_dir="${tmp_dir}/tls"
config_path="${tmp_dir}/redis.conf"
ca_path="${tls_dir}/ca.crt"
server_key_path="${tls_dir}/server.key"
server_crt_path="${tls_dir}/server.crt"
server_ext_path="${tls_dir}/server.ext"
ping_out_path="${tmp_dir}/redis-ping.out"
ping_err_path="${tmp_dir}/redis-ping.err"

cleanup() {
  if docker ps -a --format '{{.Names}}' | grep -Fxq "${container_name}"; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_REDIS_TLS_ARTIFACTS}" != "1" ]]; then
    rm -rf "${tmp_dir}"
  else
    echo "Preserving Redis TLS artifacts in ${tmp_dir}"
  fi
}
trap cleanup EXIT

mkdir -p "${tls_dir}"
# Redis runs as a non-root user in the container; ensure mounted host paths
# are traversable/readable from inside the container.
chmod 755 "${tmp_dir}" "${tls_dir}"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=veritas-redis-test-ca" \
  -keyout "${tls_dir}/ca.key" \
  -out "${ca_path}" \
  -days 1 >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=localhost" \
  -keyout "${server_key_path}" \
  -out "${tls_dir}/server.csr" >/dev/null 2>&1

cat > "${server_ext_path}" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -sha256 \
  -in "${tls_dir}/server.csr" \
  -CA "${ca_path}" \
  -CAkey "${tls_dir}/ca.key" \
  -CAcreateserial \
  -out "${server_crt_path}" \
  -days 1 \
  -extfile "${server_ext_path}" >/dev/null 2>&1

# Allow the container user to read mounted TLS files.
chmod 644 "${ca_path}" "${server_crt_path}" "${server_key_path}" \
  "${server_ext_path}" "${tls_dir}/server.csr"

cat > "${config_path}" <<EOF
bind 0.0.0.0
port 0
protected-mode no
tls-port 6380
tls-cert-file /tls/server.crt
tls-key-file /tls/server.key
tls-ca-cert-file /tls/ca.crt
tls-auth-clients no
requirepass ${redis_password}
EOF

# Allow the container user to read mounted Redis config.
chmod 644 "${config_path}"

docker run -d \
  --name "${container_name}" \
  -p "${REDIS_TLS_PORT}:6380" \
  -v "${tls_dir}:/tls:ro" \
  -v "${config_path}:/usr/local/etc/redis/redis.conf:ro" \
  "${REDIS_TLS_IMAGE}" \
  redis-server /usr/local/etc/redis/redis.conf >/dev/null

ready=0
container_exited=0
for _ in $(seq 1 40); do
  if ! docker ps --format '{{.Names}}' | grep -Fxq "${container_name}"; then
    container_exited=1
    break
  fi
  if docker exec "${container_name}" redis-cli \
      --tls \
      --cacert /tls/ca.crt \
      -a "${redis_password}" \
      ping >"${ping_out_path}" 2>"${ping_err_path}"; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "${ready}" != "1" ]]; then
  echo "Redis TLS endpoint did not become ready" >&2
  if [[ "${container_exited}" == "1" ]]; then
    echo "Redis container exited before readiness checks completed" >&2
  fi
  docker inspect "${container_name}" >/dev/null 2>&1 && \
    docker inspect -f 'state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' \
      "${container_name}" || true
  docker logs "${container_name}" || true
  if [[ -f "${ping_err_path}" ]]; then
    cat "${ping_err_path}" || true
  fi
  exit 1
fi

redis_uri="rediss://:${redis_password}@127.0.0.1:${REDIS_TLS_PORT}/0?cacert=${ca_path}&verify_peer=true"

echo "Running Redis TLS integration tests via ${BUILD_DIR}"
VERITAS_REDIS_TLS_URI="${redis_uri}" \
BUILD_TYPE="${BUILD_TYPE}" \
BUILD_DIR="${BUILD_DIR}" \
  "${ROOT_DIR}/scripts/test_redis_tls_integration.sh"
