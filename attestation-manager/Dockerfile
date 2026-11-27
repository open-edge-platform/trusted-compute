# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Start from the latest Debian trixie image
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the prebuilt executable from your host machine to the Docker image
COPY src/cmd/app/main ./main

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    chmod +x ./main

# Add a user and switch to it
USER 503

# Run the executable
CMD ["/app/main"]
