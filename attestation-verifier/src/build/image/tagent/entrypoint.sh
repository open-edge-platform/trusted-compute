#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SECRETS=/etc/secrets
IFS=$'\r\n' GLOBIGNORE='*' command eval 'secretFiles=($(ls  $SECRETS))'
for i in "${secretFiles[@]}"; do
    export $i=$(cat $SECRETS/$i)
done

export IMA_MEASURE_ENABLED=true
COMPONENT_NAME=trustagent
PRODUCT_HOME_DIR=/opt/$COMPONENT_NAME
PRODUCT_BIN_DIR=$PRODUCT_HOME_DIR/bin
CONFIG_DIR=/opt/trustagent
CA_CERTS_DIR=$CONFIG_DIR/cacerts
CERTDIR_TRUSTEDJWTCERTS=$CONFIG_DIR/jwt
CREDENTIALS_DIR=$CONFIG_DIR/credentials
CONSTANTS_VAR_DIR=$CONFIG_DIR/var
SYSTEM_INFO_DIR=$CONSTANTS_VAR_DIR/system-info
RAMFS_DIR=$CONSTANTS_VAR_DIR/ramfs

export TPM_OWNER_SECRET=
export TPM_ENDORSEMENT_SECRET=

if [ -z "$SAN_LIST" ]; then
  cp /etc/hostname /proc/sys/kernel/hostname
  #export SAN_LIST=$(hostname -i),$(hostname)
  export SAN_LIST=$(hostname -i),tc-node
  echo $SAN_LIST
fi

if [ ! -z "$TA_SERVICE_MODE" ] && [ "$TA_SERVICE_MODE" == "outbound" ]; then
  #export TA_HOST_ID=$(hostname)
  export TA_HOST_ID=tc-node
fi

if [ ! -f $CONFIG_DIR/.setup_done ]; then
  for directory in $PRODUCT_BIN_DIR $CA_CERTS_DIR $CERTDIR_TRUSTEDJWTCERTS $CREDENTIALS_DIR $CONSTANTS_VAR_DIR $SYSTEM_INFO_DIR $RAMFS_DIR; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chmod 700 $directory
    chmod g+s $directory
  done

  tagent setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi

  touch $CONFIG_DIR/.setup_done
fi

  # Create /opt/ima_policy
  # TBD: THis has to be moved to ima policy setup
  echo -e "ima_policy=tcb\nima_template=ima-ng\nima_hash=sha256" > /opt/ima_policy
  if [ $? -ne 0 ]; then
    echo "Cannot create /opt/ima_policy"
    exit 1
  fi
  chmod 600 /opt/ima_policy

if [ ! -z "$SETUP_TASK" ]; then
  cp $CONFIG_DIR/config.yml /tmp/config.yml
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    tagent setup $task --force
    if [ $? -ne 0 ]; then
      cp /tmp/config.yml $CONFIG_DIR/config.yml
      exit 1
    fi
  done
  rm -rf /tmp/config.yml
fi

for i in "${secretFiles[@]}"; do
    unset $i
done

tagent init

# Load the IMA policy
tagent ima-load-policy

# TODO: Implement a more robust solution for Wait until the IMA first measurements of all allowlist entries are completed.
sleep 60

# Log the IMA runtime measurements
cat /opt/ima/ascii_runtime_measurements

tagent startService
