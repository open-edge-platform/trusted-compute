*** Comments ***
SPDX-FileCopyrightText: (C) 2025 Intel Corporation
SPDX-License-Identifier: LicenseRef-Intel

*** Settings ***
Documentation    Trusted Workload Component Validation Test Suite
...              
...              This test suite validates trusted workload components by executing
...              various test cases. It supports an optional kubeconfig parameter
...              that can be set to specify a custom Kubernetes cluster configuration.
...              
...              Usage:
...              # Run all individual test cases (default behavior):
...              robot trusted_workload_tests.robot
...              robot -v KUBECONFIG:/path/to/kubeconfig trusted_workload_tests.robot
...              
...              # Run specific individual test cases:
...              robot --include tc1 trusted_workload_tests.robot
...              robot --include individual trusted_workload_tests.robot
...              
Library          Process
Library          String
Library          Collections
Library          OperatingSystem
Default Tags     individual    # Default behavior runs individual test cases
Suite Setup      Setup Test Environment
Suite Teardown   Cleanup Test Environment
Test Timeout     30 minutes

*** Variables ***
${SCRIPT_DIR}           ${CURDIR}
${SUCCESS_PATTERN}      [ successful ]
${FAILURE_PATTERN}      [ failed ]
${COMPLETION_PATTERN}   INFO: Test execution completed
${KUBECONFIG}           ${EMPTY}    # Optional kubeconfig file path

*** Keywords ***
Setup Test Environment
    [Documentation]    Setup the test environment before running tests
    Log    Setting up test environment for Trusted Workload validation
    
    # Verify required files exist
    File Should Exist    ${SCRIPT_DIR}/run_tests.sh
    File Should Exist    ${SCRIPT_DIR}/common_functions.sh
    File Should Exist    ${SCRIPT_DIR}/tw-component-validation-config.yaml
    
    # Verify kubeconfig file if specified
    IF    "${KUBECONFIG}" != "${EMPTY}" and "${KUBECONFIG}" != ""
        File Should Exist    ${KUBECONFIG}    msg=Kubeconfig file not found: ${KUBECONFIG}
        Log    Using kubeconfig: ${KUBECONFIG}
    ELSE
        Log    Using default kubeconfig (none specified)
    END
    
    Log    All required files found - environment ready

Cleanup Test Environment
    [Documentation]    Cleanup after all tests are completed
    Log    Test environment cleanup completed

Build Run Tests Command
    [Documentation]    Build the run_tests.sh command with optional parameters
    [Arguments]    @{args}
    
    ${command_args}=    Create List    ./run_tests.sh
    FOR    ${arg}    IN    @{args}
        Append To List    ${command_args}    ${arg}
    END
    
    # Add kubeconfig if specified
    IF    "${KUBECONFIG}" != "${EMPTY}" and "${KUBECONFIG}" != ""
        Append To List    ${command_args}    ${KUBECONFIG}
    END
    
    RETURN    ${command_args}

Run All Tests
    [Documentation]    Execute all test cases and return overall result
    
    Log    ====================================
    Log    EXECUTING ALL TRUSTED WORKLOAD TESTS
    Log    ====================================
    Log    Running complete test suite: tc1, tc2, tc3, tc4, tc5, tc6, tc7, tc8, tc9
    
    ${command_args}=    Build Run Tests Command
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=45 minutes    shell=True
    
    Log    =====================
    Log    TEST EXECUTION OUTPUT
    Log    =====================
    Log    ${result.stdout}
    
    ${has_stderr}=    Get Length    ${result.stderr}
    IF    ${has_stderr} > 0
        Log    =====================
        Log    TEST EXECUTION ERRORS
        Log    =====================
        Log    ${result.stderr}
    END
    
    # Count test results using pattern matching
    ${success_matches}=    Get Regexp Matches    ${result.stdout}    \\${SUCCESS_PATTERN}
    ${failure_matches}=    Get Regexp Matches    ${result.stdout}    \\${FAILURE_PATTERN}
    ${skipped_matches}=    Get Regexp Matches    ${result.stdout}    \\[ skipped \\]
    
    ${success_count}=    Get Length    ${success_matches}
    ${failure_count}=    Get Length    ${failure_matches}
    ${skipped_count}=    Get Length    ${skipped_matches}
    
    Log    ====================
    Log    TEST RESULTS SUMMARY
    Log    ====================
    Log    Successful Tests: ${success_count}
    Log    Failed Tests: ${failure_count}
    Log    Skipped Tests: ${skipped_count}
    
    # Check completion
    Should Contain    ${result.stdout}    ${COMPLETION_PATTERN}    Test execution should complete
    
    # Overall success if no failures and at least one success (skipped tests don't count as failures)
    ${overall_success}=    Evaluate    ${failure_count} == 0 and ${success_count} > 0
    
    RETURN    ${overall_success}    ${success_count}    ${failure_count}

Clean System
    [Documentation]    Clean the system before testing
    
    Log    ===============
    Log    CLEANING SYSTEM
    Log    ===============
    
    ${command_args}=    Build Run Tests Command    -c
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=10 minutes    shell=True
    
    Log    Clean System Output: ${result.stdout}
    Should Contain    ${result.stdout}    Cleaning system    System clean should execute properly
    
    Log    System cleaning completed successfully

*** Test Cases ***
TC1 - Individual Test Case 1
    [Documentation]    Execute individual test case 1 for trusted workload validation
    [Tags]    individual    tc1    trusted-workload    -full-suite
    
    Log    Starting TC1 - Test Case 1
    
    ${command_args}=    Build Run Tests Command    -t    tc1
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC1 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC1 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC1 should not fail
    
    Log    TC1 completed successfully

TC2 - Individual Test Case 2
    [Documentation]    Execute individual test case 2 for trusted workload validation
    [Tags]    individual    tc2    trusted-workload    -full-suite
    
    Log    Starting TC2 - Test Case 2
    
    ${command_args}=    Build Run Tests Command    -t    tc2
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC2 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC2 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC2 should not fail
    
    Log    TC2 completed successfully

TC3 - Individual Test Case 3
    [Documentation]    Execute individual test case 3 for trusted workload validation
    [Tags]    individual    tc3    trusted-workload    -full-suite
    
    Log    Starting TC3 - Test Case 3
    
    ${command_args}=    Build Run Tests Command    -t    tc3
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC3 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC3 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC3 should not fail
    
    Log    TC3 completed successfully

TC4 - Individual Test Case 4
    [Documentation]    Execute individual test case 4 for trusted workload validation
    [Tags]    individual    tc4    trusted-workload    -full-suite
    
    Log    Starting TC4 - Test Case 4
    
    ${command_args}=    Build Run Tests Command    -t    tc4
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC4 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC4 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC4 should not fail
    
    Log    TC4 completed successfully

TC5 - Individual Test Case 5
    [Documentation]    Execute individual test case 5 for trusted workload validation
    [Tags]    individual    tc5    trusted-workload    -full-suite
    
    Log    Starting TC5 - Test Case 5
    
    ${command_args}=    Build Run Tests Command    -t    tc5
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC5 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC5 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC5 should not fail
    
    Log    TC5 completed successfully

TC6 - Individual Test Case 6
    [Documentation]    Execute individual test case 6 for trusted workload validation
    [Tags]    individual    tc6    trusted-workload    -full-suite
    
    Log    Starting TC6 - Test Case 6
    
    ${command_args}=    Build Run Tests Command    -t    tc6
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC6 Output: ${result.stdout}
    
    # Check if test was skipped (for remote clusters)
    ${is_skipped}=    Run Keyword And Return Status    Should Contain    ${result.stdout}    [ skipped ]
    IF    ${is_skipped}
        Log    TC6 was skipped (remote cluster detected)
    ELSE
        Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC6 should complete successfully
        Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC6 should not fail
        Log    TC6 completed successfully
    END

TC7 - Individual Test Case 7
    [Documentation]    Execute individual test case 7 for trusted workload validation
    [Tags]    individual    tc7    trusted-workload    -full-suite
    
    Log    Starting TC7 - Test Case 7
    
    ${command_args}=    Build Run Tests Command    -t    tc7
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC7 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC7 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC7 should not fail
    
    Log    TC7 completed successfully

TC8 - Individual Test Case 8
    [Documentation]    Execute individual test case 8 for trusted workload validation
    [Tags]    individual    tc8    trusted-workload    -full-suite
    
    Log    Starting TC8 - Test Case 8
    
    ${command_args}=    Build Run Tests Command    -t    tc8
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC8 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC8 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC8 should not fail
    
    Log    TC8 completed successfully

TC9 - Individual Test Case 9
    [Documentation]    Execute individual test case 9 for trusted workload validation
    [Tags]    individual    tc9    trusted-workload    -full-suite
    
    Log    Starting TC9 - Test Case 9
    
    ${command_args}=    Build Run Tests Command    -t    tc9
    ${result}=    Run Process    @{command_args}
    ...    cwd=${SCRIPT_DIR}    timeout=15 minutes    shell=True
    
    Log    TC9 Output: ${result.stdout}
    Should Contain    ${result.stdout}    ${SUCCESS_PATTERN}    TC9 should complete successfully
    Should Not Contain    ${result.stdout}    ${FAILURE_PATTERN}    TC9 should not fail
    
    Log    TC9 completed successfully
