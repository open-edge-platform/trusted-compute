#!/usr/bin/env bash

# SPDX-FileCopyrightText: (C) 2022 Intel Corporation
# SPDX-License-Identifier: LicenseRef-Intel

set -e

PLUGIN_DIR="${HOME}/.local/share/helm/plugins/helm-unittest"
REQUIRED_VERSION="v0.8.0"

# Check if the helm-unittest plugin is already installed
if [ -d "$PLUGIN_DIR" ]; then
    INSTALLED_VERSION="v$(helm plugin list | grep 'unittest' | awk '{print $2}')"
    if [ "$INSTALLED_VERSION" == "$REQUIRED_VERSION" ]; then
        echo "helm-unittest plugin version $REQUIRED_VERSION is already installed."
    else
        echo "Updating helm-unittest plugin to version $REQUIRED_VERSION..."
        helm plugin remove unittest
        helm plugin install https://github.com/helm-unittest/helm-unittest --version=$REQUIRED_VERSION
    fi
else
    echo "Installing helm-unittest plugin version $REQUIRED_VERSION..."
    helm plugin install https://github.com/helm-unittest/helm-unittest --version=$REQUIRED_VERSION
fi

helm plugin list

# Run helm unittest
helm unittest --output-type JUnit --output-file helm-unittest-output.xml ./*/
