# Copyright (c) 2024 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause

.DEFAULT_GOAL := build

RUST_TARGET := x86_64-unknown-linux-musl
BINARY_NAME := tc-docker-deploy
TARGET_DIR := target/$(RUST_TARGET)/release

.PHONY: build
build:
	@echo "Building $(BINARY_NAME) for $(RUST_TARGET)..."
	rustup target add $(RUST_TARGET) || true
	cargo build --release --target $(RUST_TARGET)
	@echo "Binary built at: $(TARGET_DIR)/$(BINARY_NAME)"
	@ls -lh $(TARGET_DIR)/$(BINARY_NAME)

.PHONY: clean
clean:
	cargo clean
