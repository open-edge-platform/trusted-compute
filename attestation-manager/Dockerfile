# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Start from the latest Debian bookworm image
FROM debian:bookworm

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the prebuilt executable from your host machine to the Docker image
COPY src/cmd/app/main ./main

RUN chmod +x ./main

# Run the executable
CMD ["/app/main"]