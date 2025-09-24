#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

# Multi-stage: assemble only the runtime binaries/libs needed to run entrypoint.sh,
# then copy them into a distroless base so the final image is minimal.
FROM debian:bookworm-slim AS builder

# Install minimal runtime tools used by the script
RUN set -eux; \
    apt-get update && \
    apt-get install -y --no-install-recommends bash curl grep sed coreutils ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /out

# helper: collect binaries we need (bash + utilities used by the init-wait entrypoint script)
RUN set -eux; \
    mkdir -p /out/bin /out/lib /out/etc/ssl/certs; \
    cp /bin/bash /out/bin/; \
    cp /usr/bin/curl /out/bin/; \
    cp /bin/grep /out/bin/; \
    cp /usr/bin/cut /out/bin/; \
    cp /usr/bin/sed /out/bin/; \
    cp /bin/sleep /out/bin/ || true; \
    # copy ca certs
    cp -r /etc/ssl/certs /out/etc/ssl/; \
    # copy shared library dependencies for each binary found in /out/bin
    for b in /out/bin/*; do \
      ldd "$b" 2>/dev/null | awk '/=>/ {print $(NF-1)} /ld-linux/ {print $1}' | sort -u | xargs -r -I{} bash -c 'mkdir -p /out$(dirname "{}") && cp -v "{}" /out{}' ; \
    done; \
    # ensure correct perms
    chmod -R 0755 /out/bin /out/etc/ssl/certs

# Final distroless runtime image (small, no package manager)
FROM gcr.io/distroless/base-debian12@sha256:fa15492938650e1a5b87e34d47dc7d99a2b4e8aefd81b931b3f3eb6bb4c1d2f6

# copy collected runtime files from builder
COPY --from=builder /out/bin/ /bin/
COPY --from=builder /out/lib/ /lib/
COPY --from=builder /out/lib64/ /lib64/
COPY --from=builder /out/etc/ssl/ /etc/ssl/
COPY --chmod=0755 init-wait/entrypoint.sh /entrypoint.sh

# run the script with bash (bash binary was copied into /bin)
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
