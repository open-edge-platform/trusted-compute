#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


COMPONENT_NAME=authservice
LOG_PATH=/var/log/$COMPONENT_NAME

echo "Starting $COMPONENT_NAME config upgrade to v3.6.0"
chmod 640 $LOG_PATH/*
chmod 740 $LOG_PATH
echo "Completed $COMPONENT_NAME config upgrade to v3.6.0"
