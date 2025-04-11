#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SECRETS=/etc/secrets
IFS=$'\r\n' GLOBIGNORE='*' command eval 'secretFiles=($(ls  $SECRETS))'
for i in "${secretFiles[@]}"; do
    export $i=$(cat $SECRETS/$i)
done

export IMA_MEASURE_ENABLED=true
USER_ID=$(id -u)
LOG_PATH=/var/log/hvs
CONFIG_PATH=/etc/hvs
CERTS_DIR=${CONFIG_PATH}/certs
TRUSTED_CERTS=${CERTS_DIR}/trustedca
ROOT_CA_DIR=${TRUSTED_CERTS}/root
ENDORSEMENTS_CA_DIR=${CERTS_DIR}/endorsement
PRIVACY_CA_DIR=${TRUSTED_CERTS}/privacy-ca
TRUSTED_KEYS_DIR=${CONFIG_PATH}/trusted-keys
CERTDIR_TRUSTEDJWTCERTS=${CERTS_DIR}/trustedjwt
CREDENTIAL_PATH=$CONFIG_PATH/credentials
TEMPLATES_PATH=$CONFIG_PATH/templates
SCHEMA_PATH=$CONFIG_PATH/schema
export LOG_LEVEL=TRACE

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_DIR $TRUSTED_CERTS $ROOT_CA_DIR $ENDORSEMENTS_CA_DIR $PRIVACY_CA_DIR \
   $TRUSTED_KEYS_DIR $CERTDIR_TRUSTEDJWTCERTS $CREDENTIAL_PATH $TEMPLATES_PATH $SCHEMA_PATH ; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  mv /tmp/*.pem $ENDORSEMENTS_CA_DIR/
  # Copy Schema files
  cp /tmp/schema/*.json $SCHEMA_PATH/ && chmod 0600 $SCHEMA_PATH/*.json
  # Copy template files
  cp /tmp/templates/*.json $TEMPLATES_PATH/ && chmod 0600 $TEMPLATES_PATH/*.json

  hvs setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  cp $CONFIG_PATH/config.yml /tmp/config.yml
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    hvs setup $task --force
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

hvs run
