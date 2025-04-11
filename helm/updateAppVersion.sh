#!/bin/bash

# SPDX-FileCopyrightText: (C) 2022 Intel Corporation
# SPDX-License-Identifier: LicenseRef-Intel

# Check if the path is provided as an argument
if [[ -z "$1" ]]; then
    echo "Usage: $0 <path>"
    exit 1
fi

## Update the appVersion in the Chart.yaml file

# Define the path to the APP VERSION file
APP_VERSION_FILE="../$1/VERSION"

# Check if the VERSION file exists
if [[ ! -f "$APP_VERSION_FILE" ]]; then
    echo "Error: VERSION file not found at '$APP_VERSION_FILE'."
    exit 1
fi

# Read the version from the VERSION file
NEW_VERSION=$(cat "$APP_VERSION_FILE")

# Assign the input parameter to a variable
SEARCH_PATH="$1"

# Check if the provided path exists
if [[ ! -d "$SEARCH_PATH" ]]; then
    echo "Error: Path '$SEARCH_PATH' does not exist."
    exit 1
fi

# Find all Chart.yaml files in the specified path and update the appVersion
find "$SEARCH_PATH" -type f -name "Chart.yaml" | while read -r file; do
    echo "Updating appVersion in $file to $NEW_VERSION"
    sed -i "s/^appVersion:.*/appVersion: $NEW_VERSION/" "$file"
done

## Update the version in the Chart.yaml file

# Define the path to the VERSION file
VERSION_FILE="$1/VERSION"

# Check if the VERSION file exists
if [[ ! -f "$VERSION_FILE" ]]; then
    echo "Error: VERSION file not found at '$VERSION_FILE'."
    exit 1
fi

# Read the version from the VERSION file
NEW_VERSION=$(cat "$VERSION_FILE")

# Check if the provided path exists
if [[ ! -d "$SEARCH_PATH" ]]; then
    echo "Error: Path '$SEARCH_PATH' does not exist."
    exit 1
fi

# Find all Chart.yaml files in the specified path and update the version
find "$SEARCH_PATH" -type f -name "Chart.yaml" | while read -r file; do

    echo "Updating chat version in $file to $NEW_VERSION"
    sed -i "s/^version:.*/version: $NEW_VERSION/" "$file"

    echo "Updating all version fields in $file to $NEW_VERSION"
    sed -i "s/^\(\s*version:\).*/\1 $NEW_VERSION/" "$file"

done

echo "appVersion and version updated in all Chart.yaml files under '$SEARCH_PATH'."
