#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


COMPONENT_NAME=hvs
SERVICE_USERNAME=hvs

# Upgrade if component is already installed
if command -v $COMPONENT_NAME &>/dev/null; then
  n=0
  until [ "$n" -ge 3 ]
  do
  echo "$COMPONENT_NAME is already installed, Do you want to proceed with the upgrade? [y/n]"
  read UPGRADE_NEEDED
  if [ $UPGRADE_NEEDED == "y" ] || [ $UPGRADE_NEEDED == "Y" ] ; then
    echo "Proceeding with the upgrade.."
    ./${COMPONENT_NAME}_upgrade.sh
    exit $?
  elif [ $UPGRADE_NEEDED == "n" ] || [ $UPGRADE_NEEDED == "N" ] ; then
    echo "Exiting the installation.."
    exit 0
  fi
  n=$((n+1))
  done
  echo "Exiting the installation.."
  exit 0
fi

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up HVS Linux User..."
# useradd -M -> this user has no home directory
id -u $SERVICE_USERNAME 2> /dev/null || useradd -M --system --shell /sbin/nologin $SERVICE_USERNAME

echo "Installing HVS..."

PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/certs
SCHEMA_PATH=$CONFIG_PATH/schema
TEMPLATES_PATH=$CONFIG_PATH/templates
CERTDIR_TRUSTEDJWTCERTS=$CERTS_PATH/trustedjwt
CERTDIR_TRUSTEDCAS=$CERTS_PATH/trustedca/root
CERTDIR_TRUSTEDPCAS=$CERTS_PATH/trustedca/privacy-ca
KEYS_PATH=$CONFIG_PATH/trusted-keys
CERTDIR_ENDORSEMENTCA=$CERTS_PATH/endorsement
CREDENTIAL_PATH=$CONFIG_PATH/credentials

for directory in $BIN_PATH $LOG_PATH $CONFIG_PATH $CERTS_PATH $SCHEMA_PATH $CERTDIR_TRUSTEDJWTCERTS $CERTDIR_TRUSTEDCAS $CERTDIR_TRUSTEDPCAS $KEYS_PATH $CERTDIR_ENDORSEMENTCA $CREDENTIAL_PATH; do
  # mkdir -p will return 0 if directory exists or is a symlink to an existing directory or directory and parents can be created
  mkdir -p $directory
  if [ $? -ne 0 ]; then
    echo "Cannot create directory: $directory"
    exit 1
  fi
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
  chmod 700 $directory
done

chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $CONFIG_PATH
chmod -R 700 $CONFIG_PATH

cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

# Copy Endorsement CA cert
cp *.pem $CERTDIR_ENDORSEMENTCA/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $CERTDIR_ENDORSEMENTCA/*.pem

# Copy Schema files
cp -r schema/ $CONFIG_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $SCHEMA_PATH/*

# Copy template files
cp -r templates/ $CONFIG_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $TEMPLATES_PATH/*

# log file permission change
chmod 740 $LOG_PATH

# Install systemd script
cp ${COMPONENT_NAME}.service $PRODUCT_HOME && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME/${COMPONENT_NAME}.service && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME

# Enable systemd service
systemctl disable ${COMPONENT_NAME}.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/${COMPONENT_NAME}.service
systemctl daemon-reload

auto_install() {
  local component=${1}
  local cprefix=${2}
  local yum_packages=$(eval "echo \$${cprefix}_YUM_PACKAGES")
  # detect available package management tools. start with the less likely ones to differentiate.
  yum -y install $yum_packages
}

# SCRIPT EXECUTION
logRotate_clear() {
  logrotate=""
}

logRotate_detect() {
  local logrotaterc=`ls -1 /etc/logrotate.conf 2>/dev/null | tail -n 1`
  logrotate=`which logrotate 2>/dev/null`
  if [ -z "$logrotate" ] && [ -f "/usr/sbin/logrotate" ]; then
    logrotate="/usr/sbin/logrotate"
  fi
}

logRotate_install() {
  LOGROTATE_YUM_PACKAGES="logrotate"
  if [ "$(whoami)" == "root" ]; then
    auto_install "Log Rotate" "LOGROTATE"
    if [ $? -ne 0 ]; then echo "Failed to install logrotate"; exit 1; fi
  fi
  logRotate_clear; logRotate_detect;
    if [ -z "$logrotate" ]; then
      echo "logrotate is not installed"
    else
      echo  "logrotate installed in $logrotate"
    fi
}

logRotate_install

export LOG_ROTATION_PERIOD=${LOG_ROTATION_PERIOD:-weekly}
export LOG_COMPRESS=${LOG_COMPRESS:-compress}
export LOG_DELAYCOMPRESS=${LOG_DELAYCOMPRESS:-delaycompress}
export LOG_COPYTRUNCATE=${LOG_COPYTRUNCATE:-copytruncate}
export LOG_SIZE=${LOG_SIZE:-100M}
export LOG_OLD=${LOG_OLD:-12}

mkdir -p /etc/logrotate.d

if [ ! -a /etc/logrotate.d/${COMPONENT_NAME} ]; then
 echo "/var/log/${COMPONENT_NAME}/*.log {
    missingok
    notifempty
    rotate $LOG_OLD
    maxsize $LOG_SIZE
    nodateext
    $LOG_ROTATION_PERIOD
    $LOG_COMPRESS
    $LOG_DELAYCOMPRESS
    $LOG_COPYTRUNCATE
}" > /etc/logrotate.d/${COMPONENT_NAME}
fi

# find .env file 
echo PWD IS $(pwd)
if [ -f ~/${COMPONENT_NAME}.env ]; then
    echo Reading Installation options from `realpath ~/${COMPONENT_NAME}.env`
    env_file=~/${COMPONENT_NAME}.env
elif [ -f ../${COMPONENT_NAME}.env ]; then
    echo Reading Installation options from `realpath ../${COMPONENT_NAME}.env`
    env_file=../${COMPONENT_NAME}.env
fi

if [ -z $env_file ]; then
    echo "No .env file found"
    HVS_NOSETUP="true"
else
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

# check if HVS_NOSETUP is defined
if [ "${HVS_NOSETUP,,}" == "true" ]; then
    echo "HVS_NOSETUP is true, skipping setup"
    echo "Run \"$COMPONENT_NAME setup all\" for manual setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all --force -f $env_file
    SETUPRESULT=$?
    chown -R hvs:hvs /etc/hvs/
    if [ ${SETUPRESULT} == 0 ]; then
        hvs config-db-rotation
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
