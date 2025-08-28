#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC1: TW deployment in cluster

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC1
tw_deployment_in_cluster() {
    echo "============================="
    echo "TC1: TW deployment in cluster"
    echo "============================="

    if install_tw_helm_chart "$TW_HELM_CHART_VER"; then
        echo "INFO: TW deployment is ready"
        echo -e "RESULT: TW deployment in cluster [ successful ]\n"
        return 0
    else
        echo -e "RESULT: TW deployment in cluster [ failed ]\n"
        exit 1
    fi
}

################
# Main Function
################
if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_cluster_config "${1:-}"
    check_cluster_status
fi
echo "---------------------------------------------------"
check_existing_tw_helm_chart
tw_deployment_in_cluster
