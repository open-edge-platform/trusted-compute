# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Start from the latest Debian bookworm image
FROM debian:bookworm-slim@sha256:e5865e6858dacc255bead044a7f2d0ad8c362433cfaa5acefb670c1edf54dfef

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the prebuilt executable from your host machine to the Docker image
COPY src/cmd/app/main ./main

RUN chmod +x ./main

# Add a user and switch to it
USER 503

# Run the executable
CMD ["/app/main"]
