# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

mkdir -p /opt/bkc-tool/bin
mkdir -p /opt/bkc-tool/log
mkdir -p /opt/bkc-tool/log/flavor
mkdir -p /opt/bkc-tool/log/ca-cert
mkdir -p /opt/bkc-tool/log/host-manifest
mkdir -p /opt/bkc-tool/log/report
mkdir -p /opt/bkc-tool/var
touch /opt/bkc-tool/var/measure-log.json

cp *.bin /opt/bkc-tool/bin/
cp *.sh /opt/bkc-tool/bin/
cp bkc-reboot.service /opt/bkc-tool/
chmod +x /opt/bkc-tool/bin/*

ln -s /opt/bkc-tool/bin/bkc-tool.sh /usr/bin/bkc-tool

# install dependencies
TRUSTAGENT_YUM_PACKAGES="tpm2-tss-2.0.0-4.el8.x86_64 tpm2-abrmd-2.1.1-3.el8.x86_64 dmidecode redhat-lsb-core"

install_packages() {
    local yum_packages=$(eval "echo \$TRUSTAGENT_YUM_PACKAGES")

    for package in ${yum_packages}; do
        echo "Checking for dependency ${package}"
        rpm -qa | grep ${package} >/dev/null
        if [ $? -ne 0 ]; then
            echo "Installing ${package}..."
            yum -y install ${package} 
            if [ $? -ne 0 ]; then echo "Failed to install ${package} "; return 1; fi
        fi
    done
}

install_packages