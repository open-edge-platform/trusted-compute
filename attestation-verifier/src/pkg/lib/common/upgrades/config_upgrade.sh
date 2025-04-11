#!/bin/bash
#iterate over all files in "config" directory which installer must copy
# run all config upgrade scripts from current version to the latest version
# e.g. v3.5.0 to v3.7.0 upgrade should run all following scripts
# v3.5.1_{component}_config.sh
# v3.6.0_{component}_config.sh
# v3.6.1_{component}_config.sh
# v3.6.2_{component}_config.sh
# v3.7.0_{component}_config.sh
# but config update script should not run anything like
# v3.2.0_{component}_config.sh
# v3.4.0_{component}_config.sh
# v3.4.1_{component}_config.sh
# v3.5.0_{component}_config.sh
# Same applies to database scripts

#Upgrade config
#get currently installed version number after removing '.'
COMPONENT_VERSION=$(echo $1 | sed 's/v//' | sed 's/\.//g')
READ_FILES=false
BACKEDUP_CONFIG_PATH=$2
CONFIG_PATH=$3
ASSET_DIR=$4
EXT=$5
if [ -d "$ASSET_DIR" ]; then

  # Change permission only in case of systemd deployment
  if [ ! -f "/.container-env" ]; then
    chmod +x ${ASSET_DIR}/*${EXT}
  fi

  cd $ASSET_DIR
  #Sort files
  IFS=$'\r\n' GLOBIGNORE='*' command eval "configUpgradeFiles=($(ls *${EXT} | sort))"
  rm -rf temp_configs
  cd -

  for i in "${configUpgradeFiles[@]}"; do
    :
    #get script version number after removing '.'
    VERSION=$(echo $i | cut -d'_' -f1 | sed 's/v//' | sed 's/\.//g')
    #Ignore files till component version is matched
    if [ $VERSION -gt $COMPONENT_VERSION ]; then
      READ_FILES=true
    fi

    #Run all config files which are post current release
    if $READ_FILES; then
      echo "Running upgrade script - $ASSET_DIR/$i with arguments $BACKEDUP_CONFIG_PATH $CONFIG_PATH"
      $ASSET_DIR/$i $BACKEDUP_CONFIG_PATH $CONFIG_PATH
      if [ $? != 0 ]; then
        echo "Failed to apply $i upgrade script"
        exit 1
      fi
    fi
  done
fi
