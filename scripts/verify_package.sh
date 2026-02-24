#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ $# -gt 0 ]]; then
  ARCHIVES=("$@")
else
  shopt -s nullglob
  ARCHIVES=("${ROOT_DIR}"/dist/*.tar.gz)
  shopt -u nullglob
fi

if [[ ${#ARCHIVES[@]} -eq 0 ]]; then
  echo "No package archives found to verify." >&2
  exit 1
fi

for archive in "${ARCHIVES[@]}"; do
  if [[ ! -f "${archive}" ]]; then
    echo "Archive not found: ${archive}" >&2
    exit 1
  fi
  checksum_file="${archive}.sha256"
  if [[ ! -f "${checksum_file}" ]]; then
    echo "Missing checksum file: ${checksum_file}" >&2
    exit 1
  fi

  echo "Verifying archive checksum: ${archive}"
  (cd "$(dirname "${checksum_file}")" && sha256sum -c "$(basename "${checksum_file}")")

  expected_entries=(
    "/bin/veritas_gatekeeper"
    "/bin/veritas_notary"
    "/lib/libveritas.a"
    "/lib/libveritas_protocol.a"
    "/protocol/gatekeeper.proto"
    "/protocol/identity.proto"
    "/protocol/notary.proto"
    "/metadata/manifest.txt"
    "/metadata/SHA256SUMS"
  )

  listing=$(tar -tzf "${archive}")
  for suffix in "${expected_entries[@]}"; do
    if ! grep -E -q ".+${suffix}$" <<<"${listing}"; then
      echo "Archive is missing required entry '${suffix}': ${archive}" >&2
      exit 1
    fi
  done

  temp_dir=$(mktemp -d)
  trap 'rm -rf "${temp_dir}"' EXIT
  tar -xzf "${archive}" -C "${temp_dir}"
  root_entry=$(find "${temp_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  if [[ -z "${root_entry}" ]]; then
    echo "Unable to locate extracted package root for ${archive}" >&2
    exit 1
  fi

  echo "Verifying internal file checksums: ${archive}"
  (cd "${root_entry}" && sha256sum -c metadata/SHA256SUMS)
  rm -rf "${temp_dir}"
done

echo "Package verification completed successfully."
