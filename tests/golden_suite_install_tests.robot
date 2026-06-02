*** Comments ***
SPDX-FileCopyrightText: (C) 2025 Intel Corporation
SPDX-License-Identifier: LicenseRef-Intel

*** Settings ***
Documentation    Golden Suite - Trusted Compute Installation Test Suite
...
...              Installs the Trusted Compute package on a remote host via SSH,
...              then validates that all core components come up healthy.
...
...              Required variables (pass with -v):
...                DUT_HOST       -- IP or hostname of the target machine
...                DUT_USERNAME   -- SSH username
...                DUT_PASSWORD   -- SSH password
...                TC_PACKAGE    -- Local path to trusted-compute-installation-package.tgz
...
...              Optional variables:
...                DUT_PORT      -- SSH port (default: 22)
...                REMOTE_DIR    -- Working directory on the remote host (default: /home/<DUT_USERNAME>)
...                INSTALL_TIMEOUT -- Seconds to wait for install.sh to complete (default: 600)
...
...              Example:
...                robot -v DUT_HOST:192.168.100.10 \
...                      -v DUT_USERNAME:user \
...                      -v DUT_PASSWORD:user \
...                      -v TC_PACKAGE:/path/to/trusted-compute-installation-package.tgz \
...                      tests/golden_suite_install_tests.robot

Library          SSHLibrary
Library          OperatingSystem
Library          String
Library          Process

Suite Setup      Open SSH Connection To DUT
Suite Teardown   SSHLibrary.Close All Connections
Test Timeout     30 minutes

*** Variables ***
${DUT_HOST}             ${EMPTY}    # Required: IP or hostname of target DUT
${DUT_USERNAME}         ${EMPTY}    # Required: SSH username
${DUT_PASSWORD}         ${EMPTY}    # Required: SSH password
${DUT_PORT}             22
${TC_PACKAGE}           ${EMPTY}    # Required: local path to trusted-compute-installation-package.tgz
${REMOTE_DIR}           ${EMPTY}    # Optional: override remote working directory
${INSTALL_TIMEOUT}      600         # Seconds to wait for install.sh
${LOCAL_KUBECONFIG}     ${EXECDIR}/k3s.yaml
${KATA_CONFIG_PATH}     /opt/kata/share/defaults/kata-containers/configuration-qemu.toml
${KATA_CONFIG_BACKUP}    /tmp/configuration-qemu.toml.backup

*** Keywords ***
Open SSH Connection To DUT
    [Documentation]    Validate inputs and open a persistent SSH connection.
    Should Not Be Empty    ${DUT_HOST}        msg=DUT_HOST variable is required (-v DUT_HOST:<ip>)
    Should Not Be Empty    ${DUT_USERNAME}    msg=DUT_USERNAME variable is required (-v DUT_USERNAME:<user>)
    Should Not Be Empty    ${DUT_PASSWORD}    msg=DUT_PASSWORD variable is required (-v DUT_PASSWORD:<pass>)
    Should Not Be Empty    ${TC_PACKAGE}     msg=TC_PACKAGE variable is required (-v TC_PACKAGE:</path/to/pkg.tgz>)
    OperatingSystem.File Should Exist      ${TC_PACKAGE}     msg=TC_PACKAGE file not found: ${TC_PACKAGE}

    ${home_dir}=    Set Variable If    "${REMOTE_DIR}" != "${EMPTY}"
    ...    ${REMOTE_DIR}
    ...    /home/${DUT_USERNAME}

    Set Suite Variable    ${TARGET_HOST}    ${DUT_HOST}
    Set Suite Variable    ${TARGET_USERNAME}    ${DUT_USERNAME}
    Set Suite Variable    ${TARGET_PASSWORD}    ${DUT_PASSWORD}
    Set Suite Variable    ${TARGET_PORT}    ${DUT_PORT}
    Set Suite Variable    ${REMOTE_HOME}    ${home_dir}

    Log    Connecting to ${TARGET_HOST}:${TARGET_PORT} as ${TARGET_USERNAME}
    Open Connection    ${TARGET_HOST}    port=${TARGET_PORT}    timeout=30s
    Login    ${TARGET_USERNAME}    ${TARGET_PASSWORD}
    Log    SSH connection established

Upload Trusted Compute Package
    [Documentation]    SCP the installation package to the remote host.
    ${remote_pkg}=    Set Variable    ${REMOTE_HOME}/trusted-compute-installation-package.tgz
    Log    Uploading ${TC_PACKAGE} to ${TARGET_HOST}:${remote_pkg}
    Put File    ${TC_PACKAGE}    ${remote_pkg}    mode=0644
    ${out}=    Execute Command    ls -lh ${remote_pkg}
    Log    ${out}
    Set Suite Variable    ${REMOTE_PKG}    ${remote_pkg}

Extract Package On Remote
    [Documentation]    Extract the tgz on the remote host.
    Log    Extracting package on remote host
    ${stdout}    ${rc}=    Execute Command
    ...    cd ${REMOTE_HOME} && tar -xzf trusted-compute-installation-package.tgz
    ...    return_stdout=True    return_rc=True
    Log    ${stdout}
    Should Be Equal As Integers    ${rc}    0    msg=tar extraction failed (rc=${rc})
    ${out}=    Execute Command    ls ${REMOTE_HOME}/trusted-compute-installation-package/
    Log    Package contents: ${out}

Install k3s
    [Documentation]    Run the bundled k3s installer.
    Log    Installing k3s
    ${stdout}    ${rc}=    Execute Command
    ...    cd ${REMOTE_HOME}/trusted-compute-installation-package && sudo ./k3s/k3s.sh --install
    ...    return_rc=True    return_stdout=True
    Log    ${stdout}
    Should Be Equal As Integers    ${rc}    0    msg=k3s install script failed (rc=${rc})
    Log    k3s installation complete

Install Trusted Compute
    [Documentation]    Run install.sh and wait up to INSTALL_TIMEOUT seconds for completion.
    Log    Running install.sh (timeout: ${INSTALL_TIMEOUT}s)
    ${stdout}    ${rc}=    Execute Command
    ...    cd ${REMOTE_HOME}/trusted-compute-installation-package && sudo ./install.sh --k3s
    ...    return_rc=True    return_stdout=True    timeout=${INSTALL_TIMEOUT}
    Log    ${stdout}
    Should Be Equal As Integers    ${rc}    0    msg=install.sh failed (rc=${rc})
    Log    Waiting 90 seconds after installation to allow services to stabilize
    Execute Command    sleep 90
    Log    Trusted Compute installation complete

Wait For Pods Ready
    [Documentation]    Poll until all pods in trusted-compute namespace are Running/Completed,
    ...                or fail after 10 minutes.
    Log    Waiting for trusted-compute pods to become ready
    FOR    ${i}    IN RANGE    60
        ${stdout}=    Execute Command
        ...    sudo k3s kubectl get pods -n trusted-compute --no-headers 2>/dev/null || true
        Log    ${stdout}
        ${not_ready}=    Run Keyword And Return Status
        ...    Should Not Contain    ${stdout}    Pending
        ${not_ready2}=    Run Keyword And Return Status
        ...    Should Not Contain    ${stdout}    Init:
        ${not_ready3}=    Run Keyword And Return Status
        ...    Should Not Contain    ${stdout}    ContainerCreating
        ${not_ready4}=    Run Keyword And Return Status
        ...    Should Not Contain    ${stdout}    CrashLoopBackOff
        IF    """${stdout}""" != "" and "No resources found" not in """${stdout}""" and ${not_ready} and ${not_ready2} and ${not_ready3} and ${not_ready4}
            Log    All pods appear ready
            RETURN
        END
        Execute Command    sleep 10
    END
    Fail    Pods did not reach ready state within timeout

Prepare Remote Kubeconfig For Copy
    [Documentation]    Copy k3s kubeconfig to user-writable path on DUT.
    ${prep_out}    ${prep_rc}=    Execute Command
    ...    sudo cp /etc/rancher/k3s/k3s.yaml ${REMOTE_HOME}/k3s.yaml && sudo chown ${TARGET_USERNAME}:${TARGET_USERNAME} ${REMOTE_HOME}/k3s.yaml
    ...    return_stdout=True    return_rc=True
    Log    ${prep_out}
    Should Be Equal As Integers    ${prep_rc}    0    msg=Failed preparing kubeconfig on DUT (rc=${prep_rc})

Download And Patch Kubeconfig Locally
    [Documentation]    Download kubeconfig from DUT and rewrite localhost endpoint to DUT IP.
    OperatingSystem.Create Directory    vm-logs/trusted-compute-pod-logs
    SSHLibrary.Get File    ${REMOTE_HOME}/k3s.yaml    ${LOCAL_KUBECONFIG}
    ${k3s_cfg}=    OperatingSystem.Get File    ${LOCAL_KUBECONFIG}
    ${patched_cfg}=    Replace String    ${k3s_cfg}    127.0.0.1    ${TARGET_HOST}
    OperatingSystem.Create File    ${LOCAL_KUBECONFIG}    ${patched_cfg}

Ensure Local Kubectl Available
    [Documentation]    Install kubectl on runner only if it is missing.
    ${install_kubectl}=    Catenate    SEPARATOR=\n
    ...    set -euo pipefail
    ...    if ! command -v kubectl >/dev/null 2>&1; then
    ...      KUBECTL_VERSION="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
    ...      curl -L -o /tmp/kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
    ...      sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl
    ...    fi
    ...    kubectl version --client

    ${result}=    Run Process    /bin/bash    -lc    ${install_kubectl}    stdout=PIPE    stderr=STDOUT
    Log    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0    msg=Failed ensuring local kubectl (rc=${result.rc})

Collect Pod Logs Using Local Kubectl
    [Documentation]    Run local kubectl commands using patched kubeconfig and collect logs.

    Run Kubectl Command And Save Output
    ...    vm-logs/trusted-compute-pod-logs/nodes.yaml
    ...    ${TRUE}
    ...    get    nodes    -o    yaml

    Run Kubectl Command And Save Output
    ...    vm-logs/trusted-compute-pod-logs/all.log
    ...    ${TRUE}
    ...    get    all    -n    trusted-compute

    Run Kubectl Command And Save Output
    ...    vm-logs/trusted-compute-pod-logs/trusted-compute-events.log
    ...    ${TRUE}
    ...    get    events    -n    trusted-compute    --sort-by=.metadata.creationTimestamp

    Run Kubectl Command And Save Output
    ...    vm-logs/trusted-compute-pod-logs/pods-describe.log
    ...    ${TRUE}
    ...    describe    pods    -n    trusted-compute

    Collect Per Pod Logs    vm-logs/trusted-compute-pod-logs

Run Kubectl Command And Save Output
    [Documentation]    Execute kubectl with arguments and save combined stdout/stderr to file.
    [Arguments]    ${output_file}    ${allow_failure}=${FALSE}    @{kubectl_args}
    ${result}=    Run Process    kubectl    --kubeconfig    ${LOCAL_KUBECONFIG}    @{kubectl_args}    stdout=PIPE    stderr=STDOUT
    Log    kubectl @{kubectl_args}\n${result.stdout}
    OperatingSystem.Create File    ${output_file}    ${result.stdout}
    IF    not ${allow_failure}
        Should Be Equal As Integers    ${result.rc}    0    msg=kubectl command failed: kubectl @{kubectl_args}
    END

Collect Per Pod Logs
    [Documentation]    Collect pod, container, and previous container logs for trusted-compute namespace.
    [Arguments]    ${base_path}
    ${pods_result}=    Run Process    kubectl    --kubeconfig    ${LOCAL_KUBECONFIG}    get    pods    -n    trusted-compute    -o    name    stdout=PIPE    stderr=STDOUT
    Log    ${pods_result.stdout}
    Should Be Equal As Integers    ${pods_result.rc}    0    msg=Failed to list trusted-compute pods
    OperatingSystem.Create File    ${base_path}/pods-list.log    ${pods_result.stdout}

    ${pods}=    Split To Lines    ${pods_result.stdout}
    FOR    ${pod}    IN    @{pods}
        ${pod}=    Strip String    ${pod}
        IF    $pod == ''
            CONTINUE
        END

        ${pod_name}=    Replace String    ${pod}    pod/    ${EMPTY}

        Run Kubectl Command And Save Output
        ...    ${base_path}/${pod_name}.log
        ...    ${TRUE}
        ...    logs    -n    trusted-compute    ${pod_name}

        ${jsonpath_arg}=    Set Variable    jsonpath={range .spec.containers[*]}{.name}{"\\n"}{end}
        ${containers_result}=    Run Process
        ...    kubectl
        ...    --kubeconfig
        ...    ${LOCAL_KUBECONFIG}
        ...    get
        ...    pod
        ...    ${pod_name}
        ...    -n
        ...    trusted-compute
        ...    -o
        ...    ${jsonpath_arg}
        ...    stdout=PIPE
        ...    stderr=STDOUT
        Log    ${containers_result.stdout}

        ${containers}=    Split To Lines    ${containers_result.stdout}
        FOR    ${container_name}    IN    @{containers}
            ${container_name}=    Strip String    ${container_name}
            IF    $container_name == ''
                CONTINUE
            END

            Run Kubectl Command And Save Output
            ...    ${base_path}/${pod_name}-${container_name}.log
            ...    ${TRUE}
            ...    logs    -n    trusted-compute    ${pod_name}    -c    ${container_name}

            Run Kubectl Command And Save Output
            ...    ${base_path}/${pod_name}-${container_name}-previous.log
            ...    ${TRUE}
            ...    logs    -n    trusted-compute    ${pod_name}    -c    ${container_name}    --previous
        END
    END

Verify Attestation Manager Overall Trust Status
    [Documentation]    Verify attestation-manager logs contain the expected Overall Trust Status value.
    [Arguments]    ${expected_status}=true
    ${result}=    Run Process
    ...    kubectl
    ...    --kubeconfig
    ...    ${LOCAL_KUBECONFIG}
    ...    logs
    ...    -n
    ...    trusted-compute
    ...    deployment/attestation-manager
    ...    -c
    ...    attestation-manager
    ...    stdout=PIPE
    ...    stderr=STDOUT
    Log    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0    msg=Failed to fetch attestation-manager logs
    Should Contain    ${result.stdout}    Overall Trust Status: ${expected_status}    msg=Overall Trust Status did not report ${expected_status} in attestation-manager logs

Backup And Tamper Kata Configuration On DUT
    [Documentation]    Back up the Kata QEMU configuration and append a tamper marker on the DUT.
    ${backup_out}    ${backup_rc}=    Execute Command
    ...    sudo cp ${KATA_CONFIG_PATH} ${KATA_CONFIG_BACKUP}
    ...    return_stdout=True    return_rc=True
    Log    ${backup_out}
    Should Be Equal As Integers    ${backup_rc}    0    msg=Failed to back up Kata configuration on DUT

    ${tamper_out}    ${tamper_rc}=    Execute Command
    ...    sudo bash -lc 'printf "\n# golden-suite attestation tamper\n" >> ${KATA_CONFIG_PATH}'
    ...    return_stdout=True    return_rc=True
    Log    ${tamper_out}
    Should Be Equal As Integers    ${tamper_rc}    0    msg=Failed to tamper Kata configuration on DUT

Restore Kata Configuration On DUT
    [Documentation]    Restore the Kata QEMU configuration after tampering.
    ${restore_out}    ${restore_rc}=    Execute Command
    ...    sudo bash -lc 'if [ -f ${KATA_CONFIG_BACKUP} ]; then cp ${KATA_CONFIG_BACKUP} ${KATA_CONFIG_PATH} && rm -f ${KATA_CONFIG_BACKUP}; fi'
    ...    return_stdout=True    return_rc=True
    Log    ${restore_out}
    Should Be Equal As Integers    ${restore_rc}    0    msg=Failed to restore Kata configuration on DUT

Verify Attestation Manager Cordoning Message
    [Documentation]    Verify attestation-manager logs contain the text 'cordoning the node'.
    ${status_result}=    Run Process
    ...    kubectl
    ...    --kubeconfig
    ...    ${LOCAL_KUBECONFIG}
    ...    logs
    ...    -n
    ...    trusted-compute
    ...    deployment/attestation-manager
    ...    -c
    ...    attestation-manager
    ...    stdout=PIPE
    ...    stderr=STDOUT
    Log    ${status_result.stdout}
    Should Be Equal As Integers    ${status_result.rc}    0    msg=Failed to fetch attestation-manager logs for cordoning message
    Should Contain    ${status_result.stdout}    cordoning the node    msg=attestation-manager logs do not contain 'cordoning the node'

Verify Node Is SchedulingDisabled
    [Documentation]    Verify kubectl node output shows SchedulingDisabled.
    ${nodes_result}=    Run Process
    ...    kubectl
    ...    --kubeconfig
    ...    ${LOCAL_KUBECONFIG}
    ...    get
    ...    nodes
    ...    stdout=PIPE
    ...    stderr=STDOUT
    Log    ${nodes_result.stdout}
    Should Be Equal As Integers    ${nodes_result.rc}    0    msg=Failed to get nodes from cluster
    Should Contain    ${nodes_result.stdout}    SchedulingDisabled    msg=No node is marked SchedulingDisabled

Cleanup After Tamper Test
    [Documentation]    Restore tampered Kata config.
    Restore Kata Configuration On DUT

*** Test Cases ***
TC-GS-01 Upload Trusted Compute Package To DUT
    [Documentation]    Copy the Trusted Compute installation package to the DUT via SCP.
    [Tags]    golden-suite    install    upload
    Upload Trusted Compute Package

TC-GS-02 Extract Package On DUT
    [Documentation]    Extract the uploaded installation package on the DUT.
    [Tags]    golden-suite    install    extract
    Extract Package On Remote

TC-GS-03 Install k3s On DUT
    [Documentation]    Install k3s on the DUT using the bundled installer.
    [Tags]    golden-suite    install    k3s
    Install k3s

TC-GS-04 Install Trusted Compute On DUT
    [Documentation]    Run install.sh to deploy Trusted Compute on the DUT.
    [Tags]    golden-suite    install    trusted-compute
    Install Trusted Compute

TC-GS-05 Verify Trusted Compute Pods Are Running
    [Documentation]    Verify that all pods in the trusted-compute namespace reach Running state.
    [Tags]    golden-suite    validate    pods
    Wait For Pods Ready
    ${stdout}=    Execute Command
    ...    sudo k3s kubectl get pods -n trusted-compute
    Log    ${stdout}
    Should Contain    ${stdout}    Running    msg=No Running pods found in trusted-compute namespace

TC-GS-06 Verify Attestation Manager Overall Trust Status
    [Documentation]    Verify attestation-manager container logs contain 'Overall Trust Status: true'.
    [Tags]    golden-suite    validate    attestation-manager
    Prepare Remote Kubeconfig For Copy
    Download And Patch Kubeconfig Locally
    Ensure Local Kubectl Available
    Wait Until Keyword Succeeds    7 min    15 sec    Verify Attestation Manager Overall Trust Status

TC-GS-07 Verify Attestation Manager Reports False After Kata Config Tamper
    [Documentation]    Append a tamper marker to the Kata configuration on the DUT and verify attestation-manager reports Overall Trust Status: false.
    [Tags]    golden-suite    validate    attestation-manager    negative
    Backup And Tamper Kata Configuration On DUT
    Wait Until Keyword Succeeds    7 min    15 sec    Verify Attestation Manager Overall Trust Status    false
    Verify Attestation Manager Cordoning Message
    Wait Until Keyword Succeeds    3 min    15 sec    Verify Node Is SchedulingDisabled
    [Teardown]    Cleanup After Tamper Test

TC-GS-08 Collect Pod Logs
    [Documentation]    Collect trusted-compute pod logs/events.
    [Tags]    golden-suite    collect    logs
    Collect Pod Logs Using Local Kubectl
