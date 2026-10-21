#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Placeholder for an additional guest OS (e.g. Windows).

set -euo pipefail

echo "ERROR: GUEST_OS=custom is a placeholder and has no build flow yet." >&2
echo "       Implement $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/build_custom.sh, or use GUEST_OS=emt|debian." >&2
exit 1
