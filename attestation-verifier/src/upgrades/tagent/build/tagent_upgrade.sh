#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


SERVICE_NAME=tagent
CURRENT_VERSION=v5.1.0
BACKUP_PATH=${BACKUP_PATH:-"/tmp/"}
INSTALLED_EXEC_PATH="/opt/trustagent/bin/$SERVICE_NAME"
CONFIG_PATH="/opt/trustagent/configuration/"
NEW_EXEC_NAME="$SERVICE_NAME"

LOG_FILE=${LOG_FILE:-"/tmp/$SERVICE_NAME-upgrade.log"}
echo "" >$LOG_FILE
./upgrade.sh -s $SERVICE_NAME -v $CURRENT_VERSION -e $INSTALLED_EXEC_PATH -c $CONFIG_PATH -n $NEW_EXEC_NAME -b $BACKUP_PATH |& tee -a $LOG_FILE
exit_status=${PIPESTATUS[0]}
if [ $exit_status -ne 0 ]; then exit $exit_status; fi

TRUSTAGENT_USERNAME=tagent
TRUSTAGENT_VAR_DIR="/opt/trustagent/var/"
BACKUP_DIR=${BACKUP_PATH}${SERVICE_NAME}_backup

echo "Creating backup directory for default software manifests ${BACKUP_DIR}/manifests"
mkdir -p ${BACKUP_DIR}/manifests
if [ $? -ne 0 ]; then
  echo "Failed to create backup directory for default software manifests, exiting."
  exit 1
fi

echo "Backing up default software manifests to ${BACKUP_DIR}/manifests"
for filename in $(ls $TRUSTAGENT_VAR_DIR/manifest_*.xml); do
  if grep -q "Label=\"ISecL_Default" $filename; then
    mv $filename $BACKUP_DIR/manifests/
    if [ $? -ne 0 ]; then
      echo "Failed to take backup of default software manifests, exiting."
      exit 1
    fi
  fi
done

echo "Deploying new default software manifests to $TRUSTAGENT_VAR_DIR"
# copy default and workload software manifest to /opt/trustagent/var/ (application-agent)
TA_VERSION=$(tagent --version short)
UUID=$(uuidgen)
cp manifest_tpm20.xml $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
sed -i "s/Uuid=\"\"/Uuid=\"${UUID}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
sed -i "s/Label=\"ISecL_Default_Application_Flavor_v\"/Label=\"ISecL_Default_Application_Flavor_v${TA_VERSION}_TPM2.0\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml

UUID=$(uuidgen)
cp manifest_wlagent.xml $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
sed -i "s/Uuid=\"\"/Uuid=\"${UUID}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
sed -i "s/Label=\"ISecL_Default_Workload_Flavor_v\"/Label=\"ISecL_Default_Workload_Flavor_v${TA_VERSION}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml

# file ownership/permissions
chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_VAR_DIR

echo "Proceeding with upgrade of application agent"
./tbootxm_upgrade.sh -s $SERVICE_NAME -b $BACKUP_PATH |& tee -a $LOG_FILE

echo "TA upgrade completed"
