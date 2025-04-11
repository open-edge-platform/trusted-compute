#!/bin/bash

#1. Detect a version and validate if upgrade path is supported
#2. Stop service
#3. Backup data
#   - cp /opt/{component}/bin/* /tmp/{component}_backup/bin/
#   - cp /etc/{component}/* /tmp/{component}_backup/config/
#4. Refresh setup
#   - cp installer/{component} /opt/{component}/bin/
#5. Start service

help() {
  echo "
  This is a generic upgrade script intended to help upgrade components to the latest version.
      Steps:
            1. Detect a version and validate if upgrade path is supported
            2. Stop service
            3. Backup data
               - cp /opt/{component}/bin/{component} /tmp/{component}_backup/bin/
               - cp /etc/{component}/* /tmp/{component}_backup/config/
            4. Refresh setup
               - cp {component} /opt/{component}/bin/
            5. Start service

      Parameters:
       -s | --service  - Service name                # To detect a version, start and stop service
       -v | --version  - Version of latest binary    # Version of the latest binary
       -b | --backup   - Backup folder path          # Folder path for backup, default would be taken as /tmp/
       -n | --new-exec - New executable name         # New name of the executable {component}
       -o | --old-exec - Old executable name         # Old name of the executable {component}
       -e | --exec     - Executable path             # Installed executable path /opt/{component}/bin/{component}
       -c | --config   - Configuration folder path   # Configuration folder path /etc/{component}
       -l | --log      - Logging folder path         # Logging folder path, default would be taken as /var/log/
       -h | --help     - Script help                 # Script help
"
  exit 0
}

parse_param() {
  while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
    -s | --service)
      SERVICE_NAME="$2"
      shift 2
      ;;
    -v | --version)
      UPGRADE_VERSION="$2"
      shift 2
      ;;
    -b | --backup)
      BACKUP_PATH="$2"
      shift 2
      ;;
    -e | --exec)
      INSTALLED_EXEC_PATH="$2"
      shift 2
      ;;
    -c | --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    -l | --log)
      LOG_PATH="$2"
      shift 2
      ;;
    -n | --new-exec)
      NEW_EXEC_NAME="$2"
      shift 2
      ;;
    -o | --old-exec)
      OLD_EXEC_NAME="$2"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    *)
      echo "Invalid option provided - $1"
      exit 1
      ;;
    esac
  done
}

start_service() {
  if [[ ! -z "$SERVICE_NAME" ]]; then
    echo "Starting service $SERVICE_NAME"
    $SERVICE_NAME start
    exit_on_error false "Failed to start the service"
  fi
}

stop_service() {
  if [[ ! -z "$SERVICE_NAME" ]]; then
    echo "Stopping service $SERVICE_NAME"
    $SERVICE_NAME stop
    exit_on_error false "Failed to stop the service"
  fi
}

exit_on_error() {
  if [ $? != 0 ]; then
    echo "$2"
    if [ $1 == true ]; then
      start_service
    fi
    exit 1
  fi
}

check_service_stop_status() {
  if [[ ! -z "$SERVICE_NAME" ]]; then
    a=10
    SERVICE_STOPPED=false
    while [ $a -gt 0 ]; do
      $SERVICE_NAME status | grep -w 'active' &>/dev/null
      if [ $? != 0 ]; then
        SERVICE_STOPPED=true
        echo "$SERVICE_NAME service is inactive"
        break
      fi
      echo "Waiting for $a seconds for $SERVICE_NAME service to stop"
      a=$(expr $a - 1)
      sleep 1
    done
    if ! $SERVICE_STOPPED; then
      echo "Could not stop the service $SERVICE_NAME, please stop and start the $SERVICE_NAME service manually"
    fi
  fi
}

main() {
  parse_param "$@"

  #Set default path for backup if not provided
  BACKUP_PATH=${BACKUP_PATH:-"/tmp/"}
  INSTALLED_EXEC_PATH=${INSTALLED_EXEC_PATH:-"/opt/$SERVICE_NAME/bin/$SERVICE_NAME"}
  CONFIG_PATH=${CONFIG_PATH:-"/etc/$SERVICE_NAME"}
  LOG_PATH=${LOG_PATH:-"/var/log/"}
  NEW_EXEC_NAME=${NEW_EXEC_NAME:-"$SERVICE_NAME"}

  echo "Starting with the upgrade process"
  echo "Using following parameters for upgrade"
  echo "SERVICE_NAME            = ${SERVICE_NAME}"
  echo "UPGRADE_VERSION         = ${UPGRADE_VERSION}"
  echo "BACKUP_PATH             = ${BACKUP_PATH}"
  echo "INSTALLED_EXEC_PATH     = ${INSTALLED_EXEC_PATH}"
  echo "CONFIG_PATH             = ${CONFIG_PATH}"
  echo "LOG_PATH                = ${LOG_PATH}"
  echo "NEW_EXEC_NAME           = ${NEW_EXEC_NAME}"
  echo "OLD_EXEC_NAME           = ${OLD_EXEC_NAME}"

  if [ -z "$OLD_EXEC_NAME" ]; then
    OLD_EXEC_NAME=$NEW_EXEC_NAME
  fi

  INSTALLED_COMPONENT_VERSION=`$INSTALLED_EXEC_PATH --version  2> /dev/null`
  COMPONENT_VERSION=`printf "$INSTALLED_COMPONENT_VERSION" | grep Version | cut -d' ' -f2 | cut -d'-' -f1`
  if [ -z "$COMPONENT_VERSION" ]; then
    COMPONENT_VERSION=`$INSTALLED_EXEC_PATH version | grep Version | cut -d' ' -f2 | cut -d'-' -f1`
    if [ -z "$COMPONENT_VERSION" ]; then
      echo "Failed to read the component version, exiting."
      exit 1
    fi
  fi

  if [ -z "$BACKUP_ONLY" ]; then
    if [ "$UPGRADE_VERSION" = "$COMPONENT_VERSION" ]; then
      INSTALLED_BUILD_DATE=`printf "$INSTALLED_COMPONENT_VERSION" | grep 'Build Date' | awk -F"Build Date: " '{print $2}'`

      NEW_BUILD_VERSION=`./$NEW_EXEC_NAME --version`
      NEW_BUILD_DATE=`printf "$NEW_BUILD_VERSION" | grep 'Build Date' | awk -F"Build Date: " '{print $2}'`

      FORMATTED_BUILD_DATE=$(date -d $INSTALLED_BUILD_DATE "+%Y%m%d%H%M%S")
      FORMATTED_NEW_BUILD_DATE=$(date -d $NEW_BUILD_DATE "+%Y%m%d%H%M%S")

      if [ $FORMATTED_BUILD_DATE -lt $FORMATTED_NEW_BUILD_DATE ]; then
        echo "Proceeding with upgrade for the latest version of the component within release"
      else
        echo "Installed component is already up to date, no need of upgrade"
        echo "Exiting upgrade"
        exit 125
      fi
    else
      UPGRADE_MANIFEST="./manifest/supported_versions"
      IFS=$'\r\n' GLOBIGNORE='*' command eval 'SUPPORTED_VERSION=($(cat ${UPGRADE_MANIFEST}))'
      if $(echo ${SUPPORTED_VERSION[@]} | grep -q "$COMPONENT_VERSION"); then
        echo "Upgrade path from $COMPONENT_VERSION to $UPGRADE_VERSION is supported, proceeding with the upgrade"
      else
        echo "Upgrade path is not supported"
        exit 1
      fi
    fi
  fi

  echo "Running pre upgrade checks"
  ./config_upgrade.sh $COMPONENT_VERSION ${BACKUP_DIR}/config $CONFIG_PATH "./checks" ".sh"
  exit_on_error false "Failed to upgrade as upgrade checks failed."

  stop_service

  BACKUP_DIR=${BACKUP_PATH}${SERVICE_NAME}_backup
  if [[ -z "$SERVICE_NAME" ]]; then
    BACKUP_DIR=${BACKUP_PATH}${OLD_EXEC_NAME}_backup
  fi

  echo "Creating backup directory $BACKUP_DIR"
  mkdir -p $BACKUP_DIR
  exit_on_error true "Failed to create backup directory, exiting."

  echo "Creating backup directory for executable ${BACKUP_DIR}/bin"
  mkdir -p ${BACKUP_DIR}/bin
  exit_on_error true "Failed to create backup directory for executable, exiting."

  echo "Creating backup directory for configuration ${BACKUP_DIR}/config"
  mkdir -p ${BACKUP_DIR}/config
  exit_on_error true "Failed to create backup directory for configuration, exiting"

  echo "Taking backup of the executable and the configuration files"
  echo "Backing up executable to ${BACKUP_DIR}/bin"
  INSTALLED_DIR_PATH=$(dirname "${INSTALLED_EXEC_PATH}")
  cp -af ${INSTALLED_DIR_PATH}/* ${BACKUP_DIR}/bin
  exit_on_error true "Failed to take backup of executable, exiting."

  echo "Backing up configuration to ${BACKUP_DIR}/config"
  cp -af ${CONFIG_PATH}/* ${BACKUP_DIR}/config
  exit_on_error true "Failed to take backup of configuration, exiting."

  check_service_stop_status

  echo "Replacing executable to the latest version"
  \cp -f ${NEW_EXEC_NAME} ${INSTALLED_EXEC_PATH}
  exit_on_error false "Failed to copy to new executable."

  echo "Migrating Configuration if required"
  ./config_upgrade.sh $COMPONENT_VERSION ${BACKUP_DIR}/config $CONFIG_PATH "./config" ".sh"
  exit_on_error false "Failed to upgrade the configuration to the latest."

  if [ "${NEW_EXEC_NAME}" != "${OLD_EXEC_NAME}" ]; then
    echo "Updating component directories and symlinks"
    echo "Updating log location from ${LOG_PATH}${OLD_EXEC_NAME} to ${LOG_PATH}${NEW_EXEC_NAME}"
    mv ${LOG_PATH}${OLD_EXEC_NAME} ${LOG_PATH}${NEW_EXEC_NAME}
    CONFIG_DIR_PATH=$(dirname "${CONFIG_PATH}")
    echo "Updating config location from ${CONFIG_PATH} to ${CONFIG_DIR_PATH}/${NEW_EXEC_NAME}"
    mv ${CONFIG_PATH} ${CONFIG_DIR_PATH}/${NEW_EXEC_NAME}
    OLD_INSTALL_PATH=$(dirname "${INSTALLED_DIR_PATH}")
    BASE_INSTALL_PATH=$(dirname "${OLD_INSTALL_PATH}")
    if [[ -f "${OLD_INSTALL_PATH}/${OLD_EXEC_NAME}.service" ]]; then
      echo "systemctl disable ${OLD_INSTALL_PATH}/${OLD_EXEC_NAME}.service"
      systemctl disable ${OLD_INSTALL_PATH}/${OLD_EXEC_NAME}.service > /dev/null 2>&1
      systemctl daemon-reload
      echo "Updating service file name from ${OLD_INSTALL_PATH}/${OLD_EXEC_NAME}.service to ${OLD_INSTALL_PATH}/${NEW_EXEC_NAME}.service"
      touch ${OLD_INSTALL_PATH}/${NEW_EXEC_NAME}.service
      mv ${OLD_INSTALL_PATH}/${OLD_EXEC_NAME}.service ${OLD_INSTALL_PATH}/${NEW_EXEC_NAME}.service
      echo "Updating binary location from ${OLD_INSTALL_PATH}/bin/${OLD_EXEC_NAME} to ${OLD_INSTALL_PATH}/bin/${NEW_EXEC_NAME}"
      touch ${OLD_INSTALL_PATH}/bin/${NEW_EXEC_NAME}
      mv ${OLD_INSTALL_PATH}/bin/${OLD_EXEC_NAME} ${OLD_INSTALL_PATH}/bin/${NEW_EXEC_NAME}
      sed -i "s/${OLD_EXEC_NAME}/${NEW_EXEC_NAME}/g" ${OLD_INSTALL_PATH}/${NEW_EXEC_NAME}.service
    fi
    echo "Updating install location from ${OLD_INSTALL_PATH} to ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}"
    mv ${OLD_INSTALL_PATH} ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}
    if [[ -f "${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/${NEW_EXEC_NAME}.service" ]]; then
      echo "systemctl disable ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/${NEW_EXEC_NAME}.service"
      systemctl disable ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/${NEW_EXEC_NAME}.service > /dev/null 2>&1
      echo "systemctl enable ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/${NEW_EXEC_NAME}.service"
      systemctl enable ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/${NEW_EXEC_NAME}.service
      systemctl daemon-reload
      SERVICE_NAME=${NEW_EXEC_NAME}
    fi
    echo "Creating symbolic link from ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/bin/${NEW_EXEC_NAME} to /usr/bin/${NEW_EXEC_NAME}"
    ln -sfT ${BASE_INSTALL_PATH}/${NEW_EXEC_NAME}/bin/${NEW_EXEC_NAME} /usr/bin/${NEW_EXEC_NAME}
    hash ${NEW_EXEC_NAME}
  fi

  echo "Migrating Database if required"
  ./config_upgrade.sh $COMPONENT_VERSION ${BACKUP_DIR}/config $CONFIG_PATH "./database" ""
  exit_on_error false "Failed to upgrade the database to the latest."

  start_service
  echo "Upgrade to the latest version '$UPGRADE_VERSION' completed successfully"
}
main "$@"
