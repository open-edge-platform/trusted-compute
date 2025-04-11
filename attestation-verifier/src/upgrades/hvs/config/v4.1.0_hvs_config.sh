#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SERVICE_NAME=hvs
CONFIG_FILE="/etc/$SERVICE_NAME/config.yml"

echo "Starting $SERVICE_NAME config upgrade to v4.1.0"

# Add ENABLE_EKCERT_REVOKE_CHECK setting to config.yml
grep -q 'enable-ekcert-revoke-check' $CONFIG_FILE || echo 'enable-ekcert-revoke-check: false' >>$CONFIG_FILE

echo "Completed $SERVICE_NAME config upgrade to v4.1.0"