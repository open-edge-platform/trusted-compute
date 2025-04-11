#!/usr/bin/env bash

# SPDX-FileCopyrightText: (C) 2022 Intel Corporation
# SPDX-License-Identifier: LicenseRef-Intel

# Check if yamllint is installed, if not, install it
if ! command -v yamllint &> /dev/null
then
    echo "yamllint could not be found, installing..."
    pip install yamllint
    if [ $? -ne 0 ]; then
        echo "Failed to install yamllint"
        exit 1
    fi
fi

# render templates to prepare them for yamllint
for d in ./*/ ; do
    helm template "$d" --output-dir temp_dir --include-crds 
done

yamllint -d relaxed --no-warnings ./temp_dir/* | tee lint_report.txt

rm -rf temp_dir
