#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Master test runner for trusted workload component validation tests

set -uo pipefail
#set -x

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common_functions.sh"

sudo true

show_usage() {
    echo "Usage: $0 [options] [cluster_config_file]"
    echo ""
    echo "Options:"
    echo "  -h, --help                Show this help message"
    echo "  -a, --all                 Run all test cases (default)"
    echo "  -t, --test <test_case>    Run specific test case(s)"
    echo "                           Available test cases: tc1, tc2, tc3, tc4, tc5, tc6, tc7, tc8, tc9"
    echo "  -l, --list                List all available test cases"
    echo "  -c, --clean               Clean system"
    echo ""
    echo "Examples:"
    echo "  $0                                # Run all test cases"
    echo "  $0 /path/to/kubeconfig            # Run all test cases with specific kubeconfig"
    echo "  $0 -t tc1                         # Run only tc1"
    echo "  $0 -t tc1,tc2,tc3                 # Run tc1, tc2, and tc3"
    echo "  $0 -c -a                          # Clean system and run all test cases"
    echo "  $0 -l                             # List all available test cases"
}

list_test_cases() {
    echo "Available test cases:"
    echo "  tc1  - TW deployment in cluster"
    echo "  tc2  - TW uninstall in cluster"
    echo "  tc3  - Sample workload without TW deployment"
    echo "  tc4  - Sample workload with TW deployment"
    echo "  tc5  - Verify Kubernetes commands"
    echo "  tc6  - Verify files permission"
    echo "  tc7  - Verify RBAC rules"
    echo "  tc8  - Verify TW upgrade"
    echo "  tc9  - Verify logs are accessible for all pods in confidential-containers-system"
}

run_test_case() {
    local test_case="$1"
    local cluster_config_file="${2:-}"
    
    # Set environment variable to skip setup in individual test cases
    export SKIP_SETUP=1
    
    case "$test_case" in
        tc1)
            "$SCRIPT_DIR/test-cases/tc1_tw_deployment.sh" "$cluster_config_file"
            ;;
        tc2)
            "$SCRIPT_DIR/test-cases/tc2_tw_uninstall.sh" "$cluster_config_file"
            ;;
        tc3)
            "$SCRIPT_DIR/test-cases/tc3_sw_without_tw.sh" "$cluster_config_file"
            ;;
        tc4)
            "$SCRIPT_DIR/test-cases/tc4_sw_with_tw.sh" "$cluster_config_file"
            ;;
        tc5)
            "$SCRIPT_DIR/test-cases/tc5_verify_k8s_commands.sh" "$cluster_config_file"
            ;;
        tc6)
            "$SCRIPT_DIR/test-cases/tc6_verify_files_permission.sh" "$cluster_config_file"
            ;;
        tc7)
            "$SCRIPT_DIR/test-cases/tc7_verify_rbac_rules.sh" "$cluster_config_file"
            ;;
        tc8)
            "$SCRIPT_DIR/test-cases/tc8_verify_tw_upgrade.sh" "$cluster_config_file"
            ;;
        tc9)
            "$SCRIPT_DIR/test-cases/tc9_verify_cc_system_logs.sh" "$cluster_config_file"
            ;;
        *)
            echo "ERROR: Unknown test case: $test_case"
            echo "Available test cases: tc1, tc2, tc3, tc4, tc5, tc6, tc7, tc8, tc9"
            exit 1
            ;;
    esac
}

run_all_tests() {
    local cluster_config_file="${1:-}"
    
    echo "Running all test cases..."
    echo "========================="
    
    # Set up cluster configuration once for all tests
    setup_cluster_config "$cluster_config_file"
    check_cluster_status
    
    # Set environment variable to skip setup in individual test cases
    export SKIP_SETUP=1
    
    # Run test cases in sequence
    run_test_case "tc1" "$cluster_config_file"
    run_test_case "tc2" "$cluster_config_file"
    run_test_case "tc3" "$cluster_config_file"
    run_test_case "tc4" "$cluster_config_file"
    run_test_case "tc5" "$cluster_config_file"
    run_test_case "tc6" "$cluster_config_file"
    run_test_case "tc7" "$cluster_config_file"
    run_test_case "tc8" "$cluster_config_file"
    run_test_case "tc9" "$cluster_config_file"
}

# Parse command line arguments
CLEAN_SYSTEM=false
RUN_ALL=true
TEST_CASES=()
CLUSTER_CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -t|--test)
            if [[ -n "${2:-}" ]]; then
                IFS=',' read -ra TEST_CASES <<< "$2"
                RUN_ALL=false
                shift 2
            else
                echo "ERROR: --test requires a test case argument"
                exit 1
            fi
            ;;
        -l|--list)
            list_test_cases
            exit 0
            ;;
        -c|--clean)
            CLEAN_SYSTEM=true
            [[ $# -eq 1 ]] && { shift; echo "Cleaning system..."; clean_system; exit 0; }
            shift
            ;;
        -*)
            echo "ERROR: Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            # Assume it's a cluster config file
            if [[ -f "$1" ]]; then
                CLUSTER_CONFIG_FILE="$1"
            else
                echo "ERROR: File not found: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Clean system if requested
if [[ "$CLEAN_SYSTEM" == true ]]; then
    echo "Cleaning system..."
    clean_system
fi

# Run tests
if [[ "$RUN_ALL" == true ]]; then
    run_all_tests "$CLUSTER_CONFIG_FILE"
else
    # Set up cluster configuration once for selected tests
    setup_cluster_config "$CLUSTER_CONFIG_FILE"
    check_cluster_status
    
    # Set environment variable to skip setup in individual test cases
    export SKIP_SETUP=1
    
    for test_case in "${TEST_CASES[@]}"; do
        run_test_case "$test_case" "$CLUSTER_CONFIG_FILE"
    done
fi

echo "INFO: Test execution completed"
