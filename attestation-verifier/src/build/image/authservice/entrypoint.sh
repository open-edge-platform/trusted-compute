#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SECRETS=/etc/secrets
IFS=$'\r\n' GLOBIGNORE='*' command eval 'secretFiles=($(ls  $SECRETS))'
for i in "${secretFiles[@]}"; do
    export $i=$(cat $SECRETS/$i)
done

USER_ID=$(id -u)
COMPONENT_NAME=authservice
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TOKENSIGN=$CERTS_PATH/tokensign
CERTDIR_TRUSTEDJWTCAS=$CERTS_PATH/trustedca
NATS_DIR_PATH=$CONFIG_PATH/nats
NATS_NKEYS_DIR_PATH=$NATS_DIR_PATH/nkeys

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_PATH $CERTDIR_TOKENSIGN $CERTDIR_TRUSTEDJWTCAS $NATS_DIR_PATH $NATS_NKEYS_DIR_PATH; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  authservice setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  cp $CONFIG_PATH/config.yml /tmp/config.yml
  IFS=',' read -ra ADDR <<<"$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    authservice setup $task --force
    if [ $? -ne 0 ]; then
      cp /tmp/config.yml $CONFIG_PATH/config.yml
      exit 1
    fi
  done
  rm -rf /tmp/config.yml
fi

for i in "${secretFiles[@]}"; do
    unset $i
done

authservice run
