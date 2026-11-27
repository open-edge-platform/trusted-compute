#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Downloads the Debian source packages for every installed binary package whose
# copyright file matches COPYLEFT_LICENSE_REGEX and bundles them into a tarball.

set -euo pipefail

OUT_DIR="${OUT_DIR:-/out}"
TARBALL_NAME="${TARBALL_NAME:-debian-third-party-src.tar.gz}"
COPYLEFT_LICENSE_REGEX="${COPYLEFT_LICENSE_REGEX:-GPL|MPL|CDDL|EPL|EUPL|CeCILL|OSL}"

WORK_DIR="$(mktemp -d)"

# The slim image only ships "Types: deb"; apt-get source needs deb-src entries
sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
apt-get update

declare -A sources=()
while IFS=$'\t' read -r pkg src src_ver; do
    copyright="/usr/share/doc/${pkg}/copyright"
    if [[ ! -r "${copyright}" ]]; then
        echo "WARNING: No copyright file for ${pkg}; skipping"
        continue
    fi
    if grep -qiE "${COPYLEFT_LICENSE_REGEX}" "${copyright}"; then
        sources["${src}=${src_ver}"]+="${pkg} "
    fi
done < <(dpkg-query -W -f='${Package}\t${source:Package}\t${source:Version}\n')

cd "${WORK_DIR}"
for src in $(printf '%s\n' "${!sources[@]}" | sort); do
    echo "INFO: Downloading source for ${src} (binaries: ${sources[${src}]})"
    if ! apt-get source --download-only -y "${src}"; then
        echo "ERROR: Failed to download source package ${src}"
        exit 1
    fi
    printf '%s\t%s\n' "${src}" "${sources[${src}]}" >> MANIFEST.txt
done

mkdir -p "${OUT_DIR}"
tar -czf "${OUT_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" .
echo "INFO: Wrote ${OUT_DIR}/${TARBALL_NAME} with ${#sources[@]} source packages"
