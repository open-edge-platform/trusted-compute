#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SERVICE_NAME=hvs
SERVICE_USERNAME=hvs
CONFIG_DIR=$2

echo "Starting $SERVICE_NAME config upgrade to v4.0.0"
TEMPLATES_PATH=$CONFIG_DIR/templates
SCHEMA_PATH=$CONFIG_DIR/schema

mkdir -p $TEMPLATES_PATH $SCHEMA_PATH

# Change permission only in case of container environment
if [ -f "/.container-env" ]; then
  # Copy Schema files
  cp /tmp/schema/*.json $SCHEMA_PATH/
  # Copy template files
  cp /tmp/templates/*.json $TEMPLATES_PATH/
fi

if [ ! -f "/.container-env" ]; then
  # Copy template files
  cp -r templates/ $CONFIG_DIR/
  # Copy Schema files
  cp -r schema/ $CONFIG_DIR/
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $SCHEMA_PATH/
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $TEMPLATES_PATH/
fi

chmod 0600 $SCHEMA_PATH/*.json
chmod 0600 $TEMPLATES_PATH/*.json

echo "Completed $SERVICE_NAME config upgrade to v4.0.0"
