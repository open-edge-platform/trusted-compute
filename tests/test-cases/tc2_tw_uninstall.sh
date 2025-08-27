#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC2: TW uninstall in cluster

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC2
tw_uninstall_in_cluster() {
    echo ""
    echo "TC2: TW uninstall in cluster."
    echo "============================="

    if uninstall_tw_helm_chart; then 
        echo "INFO: TW deployment is uninstalled"
        echo -e "RESULT: TW uninstall in cluster [ successful ]\n"
        return 0
    else
        echo "RESULT: TW uninstall in cluster [ failed ]\n"; 
        exit 1;
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
check_existing_tw_helm_chart "skip"
tw_uninstall_in_cluster
