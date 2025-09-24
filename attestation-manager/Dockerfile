# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM gcr.io/distroless/static-debian12@sha256:87bce11be0af225e4ca761c40babb06d6d559f5767fbf7dc3c47f0f1a466b92c

# Copy the prebuilt executable from host machine to the Docker image
COPY --chmod=0755 src/cmd/app/attestation-manager /usr/local/bin/attestation-manager

# Add a user and switch to it
USER 503

# Run the executable
CMD ["attestation-manager"]