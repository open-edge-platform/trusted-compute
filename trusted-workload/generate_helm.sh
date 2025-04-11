#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

BUILD_DIR=${PWD}
COCO_OPERATOR_VERSION="v0.12.0"
COCO_OPERATOR_GITHUB="https://github.com/confidential-containers/operator.git"
COCO_OPERATOR_SRC="${BUILD_DIR}/operator"
COCO_OPERATOR_PATCH="${BUILD_DIR}/patch"
GEN_CHART_GITHUB="false"

check_package()
{
    local package="helm kubectl git basename"
    for pkg in ${package}; do
        if ! command -v "${pkg}" &> /dev/null; then
            echo "${pkg} command not found. Please install relevent package for it to work."
            exit 1
        fi
    done
}

cleanup_helm_chart()
{
    local directory="${1}"
    shift
    local whitelist=("$@")
    echo "INFO: cleaning up helm chart directory structure for $(basename ${directory})"
    find "${directory}" -type f | while read -r file; do
        local filename=$(basename "${file}")
        local in_whitelist=false
        for item in "${whitelist[@]}"; do
            if [ "${item}" == "${filename}" ]; then
                in_whitelist=true
                break
            fi
        done
        if [[ "${in_whitelist}" == false ]]; then
            rm -rf "${file}"
            #echo "Removed ${filename}"
        fi
        if [ "${filename}" == "values.yaml" ]; then > "${file}"; fi
    done
    find "${directory}" -type d -empty -delete
    mkdir -p "${directory}/templates"
}

clone_and_apply_patch()
{
    if [ -d "${COCO_OPERATOR_SRC}" ]; then rm -rf "${COCO_OPERATOR_SRC}"; fi
    git config --global advice.detachedHead false
    git clone --single-branch --depth 1 -b "${COCO_OPERATOR_VERSION}" "${COCO_OPERATOR_GITHUB}" "${COCO_OPERATOR_SRC}"
    git config advice.detachedHead false
    if [ ! -d "${COCO_OPERATOR_PATCH}" ]; then
        echo "ERROR: Patch directory not found: ${COCO_OPERATOR_PATCH}";
        exit 1
    fi
    pushd "${COCO_OPERATOR_SRC}"
    # Apply each patch file in the patch directory
    if compgen -G "${COCO_OPERATOR_PATCH}/${COCO_OPERATOR_VERSION}/*.patch" > /dev/null; then
        for patch_file in $(find "${COCO_OPERATOR_PATCH}/${COCO_OPERATOR_VERSION}" -name "*.patch"); do
            echo "Applying patch: ${patch_file}"
            git apply "${patch_file}"
        done
    else
        echo "ERROR: No patch files found in ${COCO_OPERATOR_PATCH}/${COCO_OPERATOR_VERSION}"
    fi
    popd
}

create_operator_helm_chart()
{
    local operator_name="cc-operator"
    local operator_link="github.com/confidential-containers/operator/config/release?ref=$COCO_OPERATOR_VERSION"
    local operator_whitelist=("Chart.yaml" "cc-operator-deployment.yaml" "values.yaml")

    echo "INFO: Creating helm chart for COCO operator"
    if [ -d "${operator_name}" ]; then rm -rf "${operator_name}"; fi
    helm create "${operator_name}"
    cleanup_helm_chart ${operator_name} "${operator_whitelist[@]}"
    pushd "${operator_name}"
    kubectl kustomize "${operator_link}" -o templates/"${operator_name}"-deployment.yaml
    popd
    create_helm_chart_tar "${operator_name}"
    if [ -d "${operator_name}" ]; then rm -rf "${operator_name}"; fi
}

create_helm_chart_tar()
{
    local chart_dir="${1}"
    local chart_version="0.1.0"
    local chart_name=$(basename "${chart_dir}")
    local chart_tar="${chart_name}-${chart_version}.tgz"
    echo "INFO: Creating helm chart tarball for ${chart_name} version ${chart_version}"
    pushd "${chart_dir}"
    helm package . -d "${BUILD_DIR}"
    popd
}

create_helm_chart() 
{
    create_operator_helm_chart
    local runtimeclass_name="cc-runtimeclass"
    local runtimeclass_link="github.com/confidential-containers/operator/config/samples/ccruntime/default?ref=$COCO_OPERATOR_VERSION"
    local kustomize_dir="operator/config/samples/ccruntime/default"
    local runtimeclass_name_whitelist=("Chart.yaml" "cc-operator-deployment.yaml" "values.yaml")

    #create helm chart directory structure
    echo "INFO: Creating helm chart for COCO runtime class"
    if [ -d "${runtimeclass_name}" ]; then rm -rf "${runtimeclass_name}"; fi
    helm create "${runtimeclass_name}"
    cleanup_helm_chart "${runtimeclass_name}" "${runtimeclass_name_whitelist[@]}"
    if [ "${GEN_CHART_GITHUB}" == "true" ]; then
        echo "INFO: Generating helm chart from github repository."
        clone_and_apply_patch
        pushd "${runtimeclass_name}"
        kubectl kustomize "${BUILD_DIR}/${kustomize_dir}" -o templates/"${runtimeclass_name}"-deployment.yaml
        popd
    else
        pushd "${runtimeclass_name}"
        echo "INFO: Generating helm chart from local repository."
        kubectl kustomize "${BUILD_DIR}/ccruntime/default" -o templates/"${runtimeclass_name}"-deployment.yaml
        popd
    fi
    create_helm_chart_tar "${runtimeclass_name}"
    if [ -d "${runtimeclass_name}" ]; then rm -rf "${runtimeclass_name}"; fi
    if [ -d "${COCO_OPERATOR_SRC}" ]; then rm -rf "${COCO_OPERATOR_SRC}"; fi
}

help()
{
    echo -e "\nGenerate Helm chart for COCO operator and runtime class\n"
    echo -e "Usage: $(basename "$0") [-g] [-v <version>]\n"
    echo -e "Options:"
    echo -e "  -g           : Generate CC Runtime helm chart from github repository."
    echo -e "  -v <version> : Version of the COCO operator to be used. [Default : ${COCO_OPERATOR_VERSION}]"
    echo -e "  -h           : Display this help message.\n"
    exit 1
}

########
# main #
########

# Parse command line arguments
while getopts "gv:h" opt; do
    case ${opt} in
        g ) GEN_CHART_GITHUB="true"; echo "INFO: Generating helm chart from github repository." ;;
        v ) [ -n "${OPTARG}" ] && COCO_OPERATOR_VERSION="${OPTARG}"; echo "INFO: Using COCO operator version: \"${COCO_OPERATOR_VERSION}\"" ;;
        h ) help ;;
        \? ) echo "ERROR: Invalid option provided: -${OPTARG}"; help ;;
    esac
done

# Check if required packages are installed
check_package

# Generate helm chart
create_helm_chart
