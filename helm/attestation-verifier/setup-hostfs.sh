#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


# This script should be executed on Linux RHEL Virtual Machine

EXPORT_DIRECTORY=${1}
USER_ID=${2}
CURR_DIR=`pwd`
SERVICES="cms"
SERVICES_WITH_DB="hvs authservice  shvs"
BASE_PATH=$EXPORT_DIRECTORY/isecl
LOG_PATH=logs
CONFIG_PATH=config
DB_PATH=db
VERSION=${VERSION:-0.0.8}

if [ -z "$EXPORT_DIRECTORY" ]; then
  echo "Error: missing export directory. Aborting..."
  exit 1
fi

if [ -z "$USER_ID" ]; then
  echo "Error: missing user id. Aborting..."
  exit 1
fi


# Check OS
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)


echo "Making new directory to be: ${EXPORT_DIRECTORY}"
mkdir -p ${EXPORT_DIRECTORY}

echo "Create directories for isecl services and set permissions"
services=$(eval "echo \$SERVICES")
services_db=$(eval "echo \$SERVICES_WITH_DB")

mkdir -p $BASE_PATH && chmod 777 -R $BASE_PATH
for base_service in $services; do
  service=$BASE_PATH/$base_service/$VERSION
  mkdir -p $service && chown -R $USER_ID:$USER_ID $service
  mkdir -p $service/$LOG_PATH
  mkdir -p $service/$CONFIG_PATH
  chown -R $USER_ID:$USER_ID $service/$CONFIG_PATH
  chown -R $USER_ID:$USER_ID $service/$LOG_PATH
  cd $BASE_PATH/$base_service
  ln -sfT $VERSION/$CONFIG_PATH $CONFIG_PATH
  ln -sfT $VERSION/$LOG_PATH $LOG_PATH
done

cd $CURR_DIR

for base_service in $services_db; do
  service=$BASE_PATH/$base_service/$VERSION
  mkdir -p $service && chown -R $USER_ID:$USER_ID $service
  mkdir -p $service/$LOG_PATH
  mkdir -p $service/$CONFIG_PATH
  mkdir -p $service/$DB_PATH
  chown -R $USER_ID:$USER_ID $service/$CONFIG_PATH
  chown -R $USER_ID:$USER_ID $service/$LOG_PATH
  chown -R $USER_ID:$USER_ID $service/$DB_PATH
  cd $BASE_PATH/$base_service
  ln -sfT $VERSION/$CONFIG_PATH $CONFIG_PATH
  ln -sfT $VERSION/$LOG_PATH $LOG_PATH
  ln -sfT $VERSION/$DB_PATH $DB_PATH

done
cd $CURR_DIR
chown -R $USER_ID:$USER_ID $BASE_PATH


