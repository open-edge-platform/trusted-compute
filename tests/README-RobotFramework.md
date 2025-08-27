# Robot Framework Test Suite for Trusted Workload Component Validation

This document provides comprehensive instructions for running the Robot Framework-based test automation suite for Trusted Workload component validation.

## Overview

The Robot Framework test suite (`trusted_workload_tests.robot`) provides automated testing capabilities for validating Trusted Workload components. It executes individual test cases (TC1-TC9) with detailed reporting and logging.

## Prerequisites

### Software Requirements

- **Python 3.6+**
- **Robot Framework**: `pip install robotframework`
- **Bash shell** (Linux/Unix environment)
- **Required test scripts** (must be present in the test directory):
  - `run_tests.sh` (executable)
  - `common_functions.sh`
  - `tw-component-validation-config.yaml`
  - `test-cases/` directory containing individual test case scripts

### Rboto Framwork installation

```bash
pip install robotframework
robot --version
```

## Test Suite Architecture

### Test Cases Available

| Test Case         | Description                  | Command                     |
|-------------------|-----------------------------|-----------------------------|
| **TC1**           | Individual Test Case 1       | `./run_tests.sh -t tc1`     |
| **TC2**           | Individual Test Case 2       | `./run_tests.sh -t tc2`     |
| **TC3**           | Individual Test Case 3       | `./run_tests.sh -t tc3`     |
| **TC4**           | Individual Test Case 4       | `./run_tests.sh -t tc4`     |
| **TC5**           | Individual Test Case 5       | `./run_tests.sh -t tc5`     |
| **TC6**           | Individual Test Case 6       | `./run_tests.sh -t tc6`     |
| **TC7**           | Individual Test Case 7       | `./run_tests.sh -t tc7`     |
| **TC8**           | Individual Test Case 8       | `./run_tests.sh -t tc8`     |
| **TC9**           | Individual Test Case 9       | `./run_tests.sh -t tc9`     |

## Running Tests

### Basic Usage

#### 1. Navigate to Test Directory
```bash
cd /home/kumara1/TC/com_val/trusted-compute/tests
```

#### 2. Run All Individual Test Cases (Default Behavior)

```bash
# Run all individual test cases with default kubeconfig
robot trusted_workload_tests.robot

# Run all individual test cases with custom kubeconfig
robot --variable KUBECONFIG:/path/to/kubeconfig trusted_workload_tests.robot
```

### Test Execution Modes

The test suite has been designed with different execution modes for flexibility:

#### 1. Default Mode (Recommended)
**Runs all individual test cases (TC1-TC9)**
```bash
# This is the default behavior - runs all individual test cases
robot trusted_workload_tests.robot
robot --variable KUBECONFIG:/path/to/kubeconfig trusted_workload_tests.robot
```

#### 2. Specific Individual Test Cases
**Runs selected individual test cases**
```bash
robot --include tc1 trusted_workload_tests.robot
robot --include tc1 --include tc3 trusted_workload_tests.robot
robot --variable KUBECONFIG:/path/to/kubeconfig --include tc1 trusted_workload_tests.robot
```

### Using Custom Kubeconfig

The test suite supports an optional `KUBECONFIG` parameter that allows you to specify a custom Kubernetes cluster configuration file. This is useful when testing against different clusters or when the default kubeconfig is not appropriate.

#### Examples with Kubeconfig

```bash
# Use custom kubeconfig for all tests
robot --variable KUBECONFIG:/home/user/my-cluster-config trusted_workload_tests.robot

# Use custom kubeconfig with specific test case
robot --variable KUBECONFIG:/home/user/my-cluster-config --test "TC1*" trusted_workload_tests.robot
```

### Advanced Test Execution

#### Run Individual Test Cases

```bash
# Run specific test case
robot --test "TC1*" trusted_workload_tests.robot
robot --test "TC7*" trusted_workload_tests.robot

# Run multiple specific test cases
robot --test "TC1*" --test "TC3*" --test "TC7*" trusted_workload_tests.robot

# Run with custom kubeconfig
robot --variable KUBECONFIG:/path/to/kubeconfig --test "TC1*" trusted_workload_tests.robot
```

## Test Results and Analysis

### Generated Files

After execution, Robot Framework creates:

1. **`report.html`** - Executive summary with pass/fail statistics
2. **`log.html`** - Detailed step-by-step execution log
3. **`output.xml`** - Machine-readable test results
