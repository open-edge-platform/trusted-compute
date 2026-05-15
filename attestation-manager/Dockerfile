# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Start from the latest Debian bookworm image
FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3

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
