# Trusted Workload Component Validation Tests

This directory contains individual test cases for validating trusted workload components in a Kubernetes cluster.

## File Structure

```
tests/
├── common_functions.sh           # Common functions and utilities
├── run_tests.sh                  # Master test runner
├── test-cases/                   # Individual test case files
│   ├── tc1_tw_deployment.sh          # TC1: TW deployment in cluster
│   ├── tc2_tw_uninstall.sh           # TC2: TW uninstall in cluster
│   ├── tc3_sw_without_tw.sh          # TC3: Sample workload without TW deployment
│   ├── tc4_sw_with_tw.sh             # TC4: Sample workload with TW deployment
│   ├── tc5_verify_k8s_commands.sh    # TC5: Verify Kubernetes commands
│   ├── tc6_verify_files_permission.sh # TC6: Verify files permission
│   ├── tc7_verify_rbac_rules.sh      # TC7: Verify RBAC rules
│   ├── tc8_verify_tw_upgrade.sh      # TC8: Verify TW upgrade
│   └── tc9_verify_cc_system_logs.sh  # TC9: Verify logs are accessible for all pods in confidential-containers-system
├── tw-component-validation-config.yaml # Configuration file (required)
└── README.md                     # This file
```

## Test Cases

### TC1: TW Deployment in Cluster (`tc1_tw_deployment.sh`)
- **Purpose**: Validates that the trusted workload helm chart can be successfully deployed in the cluster
- **Dependencies**: None
- **Expected Result**: TW deployment should be ready and all pods should be in Running/Completed state

### TC2: TW Uninstall in Cluster (`tc2_tw_uninstall.sh`)
- **Purpose**: Validates that the trusted workload helm chart can be successfully uninstalled from the cluster
- **Dependencies**: Requires TW to be installed (TC1)
- **Expected Result**: TW deployment should be completely removed from the cluster

### TC3: Sample Workload Without TW Deployment (`tc3_sw_without_tw.sh`)
- **Purpose**: Validates that sample workloads fail to deploy when TW is not present
- **Dependencies**: Requires TW to be uninstalled
- **Expected Result**: Sample workload installation should fail as expected

### TC4: Sample Workload With TW Deployment (`tc4_sw_with_tw.sh`)
- **Purpose**: Validates that sample workloads can deploy successfully when TW is present
- **Dependencies**: Requires TW to be installed
- **Expected Result**: Sample workload should deploy and run successfully

### TC5: Verify Kubernetes Commands (`tc5_verify_k8s_commands.sh`)
- **Purpose**: Validates that kubectl commands work correctly with the deployed workload
- **Dependencies**: Requires sample workload to be running (TC4)
- **Expected Result**: All kubectl commands (get, describe, logs) should work correctly

### TC6: Verify Files Permission (`tc6_verify_files_permission.sh`)
- **Purpose**: Validates that TW files have correct permissions on the host system
- **Dependencies**: Requires TW to be installed and local cluster access
- **Expected Result**: All TW files should have proper permissions as defined in kata_keeplist.txt

### TC7: Verify RBAC Rules (`tc7_verify_rbac_rules.sh`)
- **Purpose**: Validates that RBAC rules are properly configured for TW service accounts
- **Dependencies**: Requires TW to be installed
- **Expected Result**: Service account should have proper permissions for CRD operations

### TC8: Verify TW Upgrade (`tc8_verify_tw_upgrade.sh`)
- **Purpose**: Validates that TW can be upgraded from previous version to current version
- **Dependencies**: None (cleans system first)
- **Expected Result**: Both previous and current versions should install/uninstall successfully

### TC9: Verify CC System Logs (`tc9_verify_cc_system_logs.sh`)
- **Purpose**: Validates that logs are accessible for all pods in the confidential-containers-system namespace
- **Dependencies**: Requires TW to be installed (confidential-containers-system namespace should exist)
- **Expected Result**: All 3 pods in confidential-containers-system should have accessible logs via kubectl logs

## Usage

### Running All Tests
```bash
# Run all test cases with default kubeconfig
./run_tests.sh

# Run all test cases with specific kubeconfig
./run_tests.sh /path/to/kubeconfig

# Clean system and run all test cases
./run_tests.sh -c -a
```

### Running Individual Test Cases
```bash
# Run a single test case
./run_tests.sh -t tc1

# Run multiple specific test cases
./run_tests.sh -t tc1,tc2,tc3

# Run a specific test case with custom kubeconfig
./run_tests.sh -t tc1 /path/to/kubeconfig

```

### Running Individual Test Files Directly
```bash
# Run individual test case directly
./test-cases/tc1_tw_deployment.sh [kubeconfig_file]
./test-cases/tc2_tw_uninstall.sh [kubeconfig_file]
... etc
# 
```

### Other Options
```bash
# List all available test cases
./run_tests.sh -l

# Show help
./run_tests.sh -h
```

## Configuration

All test cases use the `tw-component-validation-config.yaml` configuration file which should contain details of:

```yaml
1. trusted workload helm chart
2. sampple workload helm chart
3. test cases details

```

## Dependencies

- `kubectl` (configured with cluster access)
- `helm` (version 3.0 or higher)
- `yq` (for YAML processing)
- `jq` (for JSON processing)
- `sudo` access (for file permission checks)

## Benefits

- **Modularity**: Each test case is self-contained and can be run independently.
- **Maintainability**: Easier to modify, debug, and extend individual test cases.
- **Reusability**: Common functions are shared across all test cases.
- **Flexibility**: Can run all tests or specific subsets as needed.
- **Debugging**: Easier to isolate and debug issues in specific test cases.
- **Documentation**: Each test case is clearly documented with its purpose and dependencies.
- **Organization**: Test cases are organized in a dedicated directory for better structure.
