#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

#--------------------------------------------------------------------------------------------------
# T R U S T A G E N T   I N S T A L L E R
#
# Overall process:
# 1. Load trustagent.env if present and apply exports.
# 2. Make sure the script is ready to be run (root user, dependencies installed, etc.). And check for upgrade.
# 3. Create tagent user
# 4. Create directories, copy files and own them by tagent user.
# 5. Install application-agent
# 6. Deploy the tagent service.
# 7. If 'automatic provisioning' is enabled (PROVISION_ATTESTATION=y), initiate 'tagent setup'.
#    Otherwise, exit with a message that the user must provision the trust agent and start the
#    service.
#--------------------------------------------------------------------------------------------------

# TERM_DISPLAY_MODE can be "plain" or "color"
TERM_DISPLAY_MODE=color
TERM_COLOR_GREEN="\\033[1;32m"
TERM_COLOR_CYAN="\\033[1;36m"
TERM_COLOR_RED="\\033[1;31m"
TERM_COLOR_YELLOW="\\033[1;33m"
TERM_COLOR_NORMAL="\\033[0;39m"

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_GREEN
# - TERM_DISPLAY_NORMAL
echo_success() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_GREEN}"; fi
  echo ${@:-"[  OK  ]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 0
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_RED
# - TERM_DISPLAY_NORMAL
echo_failure() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_RED}"; fi
  echo ${@:-"[FAILED]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_YELLOW
# - TERM_DISPLAY_NORMAL
echo_warning() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_YELLOW}"; fi
  echo ${@:-"[WARNING]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_CYAN
# - TERM_DISPLAY_NORMAL
echo_info() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_CYAN}"; fi
  echo ${@:-"[INFO]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}
#--------------------------------------------------------------------------------------------------
# Script variables
#--------------------------------------------------------------------------------------------------
DEFAULT_TRUSTAGENT_HOME=/opt/trustagent
DEFAULT_TRUSTAGENT_USERNAME=tagent

export PROVISION_ATTESTATION=${PROVISION_ATTESTATION:-n}
export TRUSTAGENT_HOME=${TRUSTAGENT_HOME:-$DEFAULT_TRUSTAGENT_HOME}

TRUSTAGENT_EXE=tagent
TRUSTAGENT_ENV_FILE=trustagent.env
TRUSTAGENT_SERVICE=tagent.service
TRUSTAGENT_INIT_SERVICE=tagent_init.service
TRUSTAGENT_BIN_DIR=$TRUSTAGENT_HOME/bin
TRUSTAGENT_LOG_DIR=/var/log/trustagent
TRUSTAGENT_CFG_DIR=/etc/trustagent
TRUSTAGENT_VAR_DIR=$TRUSTAGENT_HOME/var/
TRUSTAGENT_YUM_PACKAGES="tpm2-tss-2.0.0-4.el8.x86_64 logrotate"

#--------------------------------------------------------------------------------------------------
# 1. Load environment variable file
#--------------------------------------------------------------------------------------------------
if [ -f $USER_PWD/$TRUSTAGENT_ENV_FILE ]; then
    env_file=$USER_PWD/$TRUSTAGENT_ENV_FILE
elif [ -f ~/$TRUSTAGENT_ENV_FILE ]; then
    env_file=~/$TRUSTAGENT_ENV_FILE
fi

if [ -z "$env_file" ]; then
    echo "The trustagent.env file was not provided, 'automatic provisioning' will not be performed"
    PROVISION_ATTESTATION="false"
else
    echo "Using environment file $env_file"
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

#--------------------------------------------------------------------------------------------------
# 2. Script prerequisites
#--------------------------------------------------------------------------------------------------
echo "Starting trustagent installation from " $USER_PWD

if [[ $EUID -ne 0 ]]; then
    echo_failure "This installer must be run as root"
    exit 1
fi

COMPONENT_NAME=$TRUSTAGENT_EXE
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

# make sure tagent.service is not running or install won't work
systemctl status $TRUSTAGENT_SERVICE 2>&1 >/dev/null
if [ $? -eq 0 ]; then
    echo_failure "Please stop the tagent service before running the installer"
    exit 1
fi

install_packages() {
  local yum_packages=$(eval "echo \$TRUSTAGENT_YUM_PACKAGES")

  for package in ${yum_packages}; do
    echo "Checking for dependency ${package}"
    rpm -qa | grep ${package} >/dev/null
    if [ $? -ne 0 ]; then
        echo "Installing ${package}..."
        yum -y install ${package}
        if [ $? -ne 0 ]; then echo_failure "Failed to install ${package} "; return 1; fi
    fi
  done
}

install_packages

# check if a command is already on path
is_command_available() {
  which $* > /dev/null 2>&1
  local result=$?
  if [ $result -eq 0 ]; then return 0; else return 1; fi
}

is_txtstat_installed() {
  is_command_available txt-stat
}

is_measured_launch() {
  local mle=$(txt-stat | grep 'TXT measured launch: TRUE')
  if [ -n "$mle" ]; then
    return 0
  else
    return 1
  fi
}

is_uefi_boot() {
  if [ -d /sys/firmware/efi ]; then
    return 0
  else
    return 1
  fi
}

define_grub_file() {
  if is_uefi_boot; then
    if [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
      DEFAULT_GRUB_FILE="/boot/efi/EFI/redhat/grub.cfg"
    fi
  else
    if [ -f "/boot/grub2/grub.cfg" ]; then
      DEFAULT_GRUB_FILE="/boot/grub2/grub.cfg"
    fi
  fi
  GRUB_FILE=${GRUB_FILE:-$DEFAULT_GRUB_FILE}
}

is_tpm_driver_loaded() {
  define_grub_file

  if [ ! -e /dev/tpm0 ]; then
    local is_tpm_tis_force=$(grep '^GRUB_CMDLINE_LINUX' /etc/default/grub | grep 'tpm_tis.force=1')
    local is_tpm_tis_force_any=$(grep '^GRUB_CMDLINE_LINUX' /etc/default/grub | grep 'tpm_tis.force')
    if [ -n "$is_tpm_tis_force" ]; then
      echo "TPM driver not loaded, tpm_tis.force=1 already in /etc/default/grub"
    elif [ -n "$is_tpm_tis_force_any" ]; then
      echo "TPM driver not loaded, tpm_tis.force present but disabled in /etc/default/grub"
    else
      sed -i -e '/^GRUB_CMDLINE_LINUX/ s/"$/ tpm_tis.force=1"/' /etc/default/grub
      is_tpm_tis_force=$(grep '^GRUB_CMDLINE_LINUX' /etc/default/grub | grep 'tpm_tis.force=1')
      if [ -n "$is_tpm_tis_force" ]; then
        echo "TPM driver not loaded, added tpm_tis.force=1 to /etc/default/grub"
        grub2-mkconfig -o $GRUB_FILE
      else
        echo "TPM driver not loaded, failed to add tpm_tis.force=1 to /etc/default/grub"
      fi
    fi
    return 1
  fi
  return 0
}

is_reboot_required() {
  local should_reboot=no
  if is_txtstat_installed; then
    if ! is_measured_launch; then
      echo_warning "Not in measured launch environment, reboot required"
      should_reboot=yes
    else
      echo "Already in measured launch environment"
    fi
  fi

  if ! is_tpm_driver_loaded; then
    echo_warning "TPM driver is not loaded, reboot required"
    should_reboot=yes
  else
    echo "TPM driver is already loaded"
  fi

  if [ "$should_reboot" == "yes" ]; then
    return 0
  else
    return 1
  fi
}

is_reboot_required
rebootRequired=$?

export LOG_ROTATION_PERIOD=${LOG_ROTATION_PERIOD:-weekly}
export LOG_COMPRESS=${LOG_COMPRESS:-compress}
export LOG_DELAYCOMPRESS=${LOG_DELAYCOMPRESS:-delaycompress}
export LOG_COPYTRUNCATE=${LOG_COPYTRUNCATE:-copytruncate}
export LOG_SIZE=${LOG_SIZE:-100M}
export LOG_OLD=${LOG_OLD:-12}

mkdir -p /etc/logrotate.d

if [ ! -a /etc/logrotate.d/trustagent ]; then
  echo "/var/log/trustagent/*.log {
    missingok
    notifempty
    rotate $LOG_OLD
    maxsize $LOG_SIZE
    nodateext
    $LOG_ROTATION_PERIOD
    $LOG_COMPRESS
    $LOG_DELAYCOMPRESS
    $LOG_COPYTRUNCATE
}" >/etc/logrotate.d/trustagent
fi

#--------------------------------------------------------------------------------------------------
# 3. Create tagent user
#--------------------------------------------------------------------------------------------------
TRUSTAGENT_USERNAME=${TRUSTAGENT_USERNAME:-$DEFAULT_TRUSTAGENT_USERNAME}
if ! getent passwd $TRUSTAGENT_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Trust Agent User" --home $TRUSTAGENT_HOME --system --shell /bin/false $TRUSTAGENT_USERNAME
    usermod --lock $TRUSTAGENT_USERNAME
fi

# to access tpm etc.
usermod -a -G tss $TRUSTAGENT_USERNAME

#--------------------------------------------------------------------------------------------------
# 4. Setup directories, copy files and own them
#--------------------------------------------------------------------------------------------------
mkdir -p $TRUSTAGENT_HOME
mkdir -p $TRUSTAGENT_BIN_DIR
mkdir -p $TRUSTAGENT_CFG_DIR
mkdir -p $TRUSTAGENT_LOG_DIR
mkdir -p $TRUSTAGENT_VAR_DIR
mkdir -p $TRUSTAGENT_VAR_DIR/system-info
mkdir -p $TRUSTAGENT_VAR_DIR/ramfs
mkdir -p $TRUSTAGENT_CFG_DIR/cacerts
mkdir -p $TRUSTAGENT_CFG_DIR/jwt
mkdir -p $TRUSTAGENT_CFG_DIR/credentials

# copy 'tagent' to bin dir
cp $TRUSTAGENT_EXE $TRUSTAGENT_BIN_DIR/

# make a link in /usr/bin to tagent...
ln -sfT $TRUSTAGENT_BIN_DIR/$TRUSTAGENT_EXE /usr/bin/$TRUSTAGENT_EXE

# Install systemd scripts
cp $TRUSTAGENT_SERVICE $TRUSTAGENT_HOME
cp $TRUSTAGENT_INIT_SERVICE $TRUSTAGENT_HOME

# copy default and workload software manifest to /opt/trustagent/var/ (application-agent)
if ! stat $TRUSTAGENT_VAR_DIR/manifest_* 1>/dev/null 2>&1; then
    TA_VERSION=$(tagent --version short)
    UUID=$(uuidgen)
    cp manifest_tpm20.xml $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Uuid=\"\"/Uuid=\"${UUID}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Label=\"ISecL_Default_Application_Flavor_v\"/Label=\"ISecL_Default_Application_Flavor_v${TA_VERSION}_TPM2.0\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml

    UUID=$(uuidgen)
    cp manifest_wlagent.xml $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Uuid=\"\"/Uuid=\"${UUID}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Label=\"ISecL_Default_Workload_Flavor_v\"/Label=\"ISecL_Default_Workload_Flavor_v${TA_VERSION}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
fi

# file ownership/permissions
chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_HOME
chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_LOG_DIR
chmod 700 $TRUSTAGENT_BIN_DIR/*

# log file permission change
chmod 740 $TRUSTAGENT_LOG_DIR

# make sure /tmp is writable -- this is needed when the 'trustagent/v2/application-measurement' endpoint
# calls /opt/tbootxm/bin/measure.
# TODO:  Resolve this in lib-workload-measure (hard coded path)
chmod 1777 /tmp

# TODO:  remove the dependency that tpmextend has on the tpm version in /opt/trustagent/configuration/tpm-version
if [ -f "$TRUSTAGENT_CFG_DIR/tpm-version" ]; then
    rm -f $TRUSTAGENT_CFG_DIR/tpm-version
fi
echo "2.0" >$TRUSTAGENT_CFG_DIR/tpm-version

#--------------------------------------------------------------------------------------------------
# 5. Install application-agent
#--------------------------------------------------------------------------------------------------
if [[ ${container} == "docker" ]]; then
    DOCKER=true
else
    DOCKER=false
fi

if [[ ${DOCKER} == "false" ]]; then
  if [ "$TBOOTXM_INSTALL" != "N" ] && [ "$TBOOTXM_INSTALL" != "No" ] && [ "$TBOOTXM_INSTALL" != "n" ] && [ "$TBOOTXM_INSTALL" != "no" ]; then
    echo "Installing application-agent..."
    TBOOTXM_PACKAGE=`ls -1 application-agent*.bin 2>/dev/null | tail -n 1`
    if [ -z "$TBOOTXM_PACKAGE" ]; then
      echo_failure "Failed to find application-agent installer package"
      exit 1
    fi
    ./$TBOOTXM_PACKAGE
    if [ $? -ne 0 ]; then echo_failure "Failed to install application-agent"; exit 1; fi
  fi
fi

#--------------------------------------------------------------------------------------------------
# 6. Enable/configure services, etc.
#--------------------------------------------------------------------------------------------------
# make sure the tss user owns /dev/tpmrm0 (this file does not
# exist when using the tpm simulator, so check for its existence)
if [ -c /dev/tpmrm0 ]; then
    chown tss:tss /dev/tpmrm0
fi


# Enable tagent service and tagent 'init' service
systemctl disable $TRUSTAGENT_INIT_SERVICE >/dev/null 2>&1
systemctl enable $TRUSTAGENT_HOME/$TRUSTAGENT_INIT_SERVICE
systemctl disable $TRUSTAGENT_SERVICE >/dev/null 2>&1
systemctl enable $TRUSTAGENT_HOME/$TRUSTAGENT_SERVICE
systemctl daemon-reload

#--------------------------------------------------------------------------------------------------
# 5. If automatic provisioning is enabled, do it here...
#--------------------------------------------------------------------------------------------------
if [[ "$PROVISION_ATTESTATION" == "y" || "$PROVISION_ATTESTATION" == "Y" || "$PROVISION_ATTESTATION" == "yes" ]]; then
    echo "Automatic provisioning is enabled, using HVS url $HVS_URL"

    $TRUSTAGENT_EXE setup all --force
    setup_results=$?

    if [ $setup_results -eq 0 ]; then

        systemctl start $TRUSTAGENT_SERVICE
        echo "Waiting for $TRUSTAGENT_SERVICE to start"
        sleep 5

        systemctl status $TRUSTAGENT_SERVICE 2>&1 >/dev/null
        if [ $? -ne 0 ]; then
            echo_failure "Installation completed with errors - $TRUSTAGENT_SERVICE did not start."
            echo_failure "Please check errors in syslog using \`journalctl -u $TRUSTAGENT_SERVICE\`"
            exit 1
        fi

        echo "$TRUSTAGENT_SERVICE is running"

        if [[ "$AUTOMATIC_REGISTRATION" == "y" || "$AUTOMATIC_REGISTRATION" == "Y" || "$AUTOMATIC_REGISTRATION" == "yes" ]]; then
            echo "Automatically registering host with HVS..."
            tagent setup create-host
            tagent setup create-host-unique-flavor
        fi

        if [[ "$AUTOMATIC_PULL_MANIFEST" == "y" || "$AUTOMATIC_PULL_MANIFEST" == "Y" || "$AUTOMATIC_PULL_MANIFEST" == "yes" ]]; then
            echo "Automatically pulling application-manifests from HVS..."
            tagent setup get-configured-manifest
        fi
    else
        echo_failure "'$TRUSTAGENT_EXE setup' failed"
        exit 1
    fi
else
    echo ""
    echo "Automatic provisioning is disabled. You must use 'tagent setup trustagent.env' command to complete (see tagent --help)"
    echo "The tagent service must also be started using command 'tagent start'"
fi

echo_success "Installation succeeded"

if [[ $rebootRequired -eq 0 ]] && [[ $SUEFI_ENABLED == "false" ]]; then
    echo
    echo "Trust Agent: A reboot is required."
    echo
fi