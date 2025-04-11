#!/bin/bash

exit_on_error() {
  if [ $? != 0 ]; then
    echo "$1"
    exit 1
  fi
}

help() {
  echo "
  This is a generic upgrade script intended to help upgrade config and database changes of component to the latest version.

  Usage: ./container-upgrade.sh [-h|-help|help]

  Required environment variables
  COMPONENT_VERSION: Existing version of deployed container image
  CONFIG_DIR:        Config directory of service/agent
"
  exit 0
}

main() {

  if [ "$1" == "help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    help "$@"
  fi

  echo "Migrating Configuration if required"
  ./config_upgrade.sh $COMPONENT_VERSION $CONFIG_DIR $CONFIG_DIR "./config" ".sh"
  exit_on_error "Failed to upgrade the configuration to the latest."

  echo "Migrating Database if required"
  ./config_upgrade.sh $COMPONENT_VERSION $CONFIG_DIR $CONFIG_DIR "./database" ""
  exit_on_error "Failed to upgrade the database to the latest."

}

main "$@"