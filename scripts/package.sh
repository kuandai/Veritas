#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

: "${CONAN_HOME:=${ROOT_DIR}/.conan}"
export CONAN_HOME

DIST_DIR="${ROOT_DIR}/dist"
mkdir -p "${DIST_DIR}"

cat <<'NOTE'
Packaging is a placeholder.

Suggested next steps:
- Decide on container images (gatekeeper/notary).
- Add install targets + CPack if tarballs are desired.
- Wire CI to produce artifacts.
NOTE

exit 1
