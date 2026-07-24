#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

DOCKERFILE="${1:?Usage: $0 <path-to-Dockerfile>}"
[ -f "${DOCKERFILE}" ] || { echo "ERROR: Dockerfile not found: ${DOCKERFILE}"; exit 1; }

# adds: zstd -dc "${DESTINATION}/tarballs/kata-deploy-static-tc-docker-deploy.tar.zst" | tar -xf - -C /opt/prebuilt
awk '
/kata-deploy-static-nydus-snapshotter-for-coco-guest-pull\.tar\.zst[^&]*\/opt\/prebuilt$/ {
    print $0 " && \\"
    print "\tzstd -dc \"${DESTINATION}/tarballs/kata-deploy-static-tc-docker-deploy.tar.zst\" | tar -xf - -C /opt/prebuilt"
    next
}
{ print }
' "${DOCKERFILE}" > "${DOCKERFILE}.tmp" && mv "${DOCKERFILE}.tmp" "${DOCKERFILE}"

# adds: COPY --from=artifact-stage /opt/prebuilt/usr/bin/tc-docker-deploy /usr/bin/tc-docker-deploy
awk '
/^COPY --from=artifact-stage \/opt\/prebuilt\/usr\/bin\/kata-deploy \/usr\/bin\/kata-deploy$/ {
    print
    print "COPY --from=artifact-stage /opt/prebuilt/usr/bin/tc-docker-deploy /usr/bin/tc-docker-deploy"
    next
}
{ print }
' "${DOCKERFILE}" > "${DOCKERFILE}.tmp" && mv "${DOCKERFILE}.tmp" "${DOCKERFILE}"

echo "INFO: Dockerfile patched successfully"
