#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SERVICE_NAME=hvs
CURRENT_VERSION=v5.1.0
BACKUP_PATH=${BACKUP_PATH:-"/tmp/"}
LOG_FILE=${LOG_FILE:-"/tmp/$SERVICE_NAME-upgrade.log"}
echo "" >$LOG_FILE
./upgrade.sh -s $SERVICE_NAME -v $CURRENT_VERSION -b $BACKUP_PATH |& tee -a $LOG_FILE
exit ${PIPESTATUS[0]}
