#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

USER_PRESETS="${ROOT_DIR}/CMakeUserPresets.json"
if [[ ! -f "${USER_PRESETS}" ]]; then
  exit 0
fi

python3 - "${USER_PRESETS}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
root = path.parent

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    # This file is developer-local; avoid breaking builds if it gets corrupted.
    sys.exit(0)

includes = data.get("include")
if not isinstance(includes, list):
    sys.exit(0)

new_includes = []
seen = set()
for item in includes:
    if not isinstance(item, str):
        continue
    if item in seen:
        continue
    seen.add(item)
    if (root / item).exists():
        new_includes.append(item)

if new_includes != includes:
    data["include"] = new_includes
    path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
PY

