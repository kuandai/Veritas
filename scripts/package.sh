#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${BUILD_DIR:=${ROOT_DIR}/build}"
: "${DIST_DIR:=${ROOT_DIR}/dist}"
: "${PACKAGE_NAME:=veritas}"
: "${VERIFY_PACKAGE:=true}"

if [[ -n "${PACKAGE_VERSION:-}" ]]; then
  VERSION="${PACKAGE_VERSION}"
elif git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  VERSION=$(git -C "${ROOT_DIR}" describe --always --dirty)
else
  VERSION="unknown"
fi

PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
ARCHIVE_BASE="${PACKAGE_NAME}-${VERSION}-${PLATFORM}"
ARCHIVE_PATH="${DIST_DIR}/${ARCHIVE_BASE}.tar.gz"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

REQUIRED_FILES=(
  "${BUILD_DIR}/services/gatekeeper/veritas_gatekeeper"
  "${BUILD_DIR}/services/notary/veritas_notary"
  "${BUILD_DIR}/libveritas/libveritas.a"
  "${BUILD_DIR}/protocol/libveritas_protocol.a"
)

for file in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "Missing required build artifact: ${file}" >&2
    echo "Run ./scripts/build.sh (or equivalent CMake build) first." >&2
    exit 1
  fi
done

mkdir -p "${DIST_DIR}"

stage_dir=$(mktemp -d)
cleanup() {
  rm -rf "${stage_dir}"
}
trap cleanup EXIT

package_root="${stage_dir}/${ARCHIVE_BASE}"
mkdir -p "${package_root}/bin" "${package_root}/lib" \
         "${package_root}/include" "${package_root}/protocol" \
         "${package_root}/metadata"

install -m 0755 "${BUILD_DIR}/services/gatekeeper/veritas_gatekeeper" \
  "${package_root}/bin/veritas_gatekeeper"
install -m 0755 "${BUILD_DIR}/services/notary/veritas_notary" \
  "${package_root}/bin/veritas_notary"
install -m 0644 "${BUILD_DIR}/libveritas/libveritas.a" \
  "${package_root}/lib/libveritas.a"
install -m 0644 "${BUILD_DIR}/protocol/libveritas_protocol.a" \
  "${package_root}/lib/libveritas_protocol.a"

cp -R "${ROOT_DIR}/libveritas/include/." "${package_root}/include/"
cp -R "${ROOT_DIR}/protocol/." "${package_root}/protocol/"

if git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GIT_COMMIT=$(git -C "${ROOT_DIR}" rev-parse HEAD)
else
  GIT_COMMIT="unknown"
fi

cat >"${package_root}/metadata/manifest.txt" <<EOF
package_name=${PACKAGE_NAME}
package_version=${VERSION}
platform=${PLATFORM}
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git_commit=${GIT_COMMIT}
build_dir=${BUILD_DIR}
EOF

(
  cd "${package_root}"
  find bin include lib protocol metadata -type f ! -path "metadata/SHA256SUMS" \
    | sort | xargs sha256sum > metadata/SHA256SUMS
)

tar -C "${stage_dir}" -czf "${ARCHIVE_PATH}" "${ARCHIVE_BASE}"
sha256sum "${ARCHIVE_PATH}" > "${CHECKSUM_PATH}"

echo "Created package: ${ARCHIVE_PATH}"
echo "Created checksum: ${CHECKSUM_PATH}"

if [[ "${VERIFY_PACKAGE}" == "true" ]]; then
  "${ROOT_DIR}/scripts/verify_package.sh" "${ARCHIVE_PATH}"
fi
