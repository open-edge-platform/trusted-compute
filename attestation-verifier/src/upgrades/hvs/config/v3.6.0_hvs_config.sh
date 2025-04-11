#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SERVICE_NAME=hvs
CONFIG_FILE="/etc/$SERVICE_NAME/config.yml"
LOG_PATH=/var/log/$SERVICE_NAME

echo "Starting $SERVICE_NAME config upgrade to v3.6.0"
# Update default value of host trust cache
sed -ri 's/^(\s*)(host-trust-cache-threshold\s*:\s*0\s*$)/\1host-trust-cache-threshold: 100000/' $CONFIG_FILE

chmod 640 $LOG_PATH/*
chmod 740 $LOG_PATH
echo "Completed $SERVICE_NAME config upgrade to v3.6.0"
