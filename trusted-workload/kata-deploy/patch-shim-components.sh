#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

SHIM_COMPONENTS_JSON="${1:-}"
KATA_TAG="${2:-}"
[ -n "${SHIM_COMPONENTS_JSON}" ] && [ -n "${KATA_TAG}" ] || { echo "ERROR: both arguments required: <shim-components.json> <kata-tag>"; exit 1; }
[ -f "${SHIM_COMPONENTS_JSON}" ] || { echo "ERROR: File not found: ${SHIM_COMPONENTS_JSON}"; exit 1; }

cat > "${SHIM_COMPONENTS_JSON}" <<EOF
{
  "_comment": [
    "Maps each runtime class to the component tarballs it requires per architecture.",
    "All names correspond directly to kata-static-<name>.tar.zst build artifacts."
  ],
  "shims": {
    "qemu": {
      "x86_64": ["${KATA_TAG}-amd64"]
    }
  }
}
EOF

echo "INFO: shim-components.json patched: qemu/x86_64 -> [\"${KATA_TAG}-amd64\"]"
