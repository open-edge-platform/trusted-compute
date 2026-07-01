*** Comments ***
SPDX-FileCopyrightText: (C) 2026 Intel Corporation
SPDX-License-Identifier: LicenseRef-Intel

*** Settings ***
Documentation    Golden Suite - Trusted Compute Docker Installation Test Suite
...              Installs the Trusted Compute package on a remote host via SSH
...              with Docker mode enabled, then validates docker-compose assets.

Library          SSHLibrary
Library          OperatingSystem
Library          String

Suite Setup      Open SSH Connection To DUT
Suite Teardown   SSHLibrary.Close All Connections
Test Timeout     20 minutes

*** Variables ***
${DUT_HOST}             ${EMPTY}    # Required: IP or hostname of target DUT
${DUT_USERNAME}         ${EMPTY}    # Required: SSH username
${DUT_PASSWORD}         ${EMPTY}    # Required: SSH password
${DUT_PORT}             22
${TC_PACKAGE}           ${EMPTY}    # Required: local path to trusted-compute-installation-package.tgz
${REMOTE_DIR}           ${EMPTY}    # Optional: override remote working directory
${INSTALL_TIMEOUT}      600         # Seconds to wait for install.sh

*** Keywords ***
Open SSH Connection To DUT
    [Documentation]    Validate inputs and open a persistent SSH connection.
    Should Not Be Empty    ${DUT_HOST}        msg=DUT_HOST variable is required (-v DUT_HOST:<ip>)
    Should Not Be Empty    ${DUT_USERNAME}    msg=DUT_USERNAME variable is required (-v DUT_USERNAME:<user>)
    Should Not Be Empty    ${DUT_PASSWORD}    msg=DUT_PASSWORD variable is required (-v DUT_PASSWORD:<pass>)
    Should Not Be Empty    ${TC_PACKAGE}      msg=TC_PACKAGE variable is required (-v TC_PACKAGE:</path/to/pkg.tgz>)
    OperatingSystem.File Should Exist    ${TC_PACKAGE}    msg=TC_PACKAGE file not found: ${TC_PACKAGE}

    ${home_dir}=    Set Variable If    "${REMOTE_DIR}" != "${EMPTY}"
    ...    ${REMOTE_DIR}
    ...    /home/${DUT_USERNAME}

    Set Suite Variable    ${TARGET_HOST}    ${DUT_HOST}
    Set Suite Variable    ${TARGET_USERNAME}    ${DUT_USERNAME}
    Set Suite Variable    ${TARGET_PASSWORD}    ${DUT_PASSWORD}
    Set Suite Variable    ${TARGET_PORT}    ${DUT_PORT}
    Set Suite Variable    ${REMOTE_HOME}    ${home_dir}

    Open Connection    ${TARGET_HOST}    port=${TARGET_PORT}    timeout=30s
    Login    ${TARGET_USERNAME}    ${TARGET_PASSWORD}

Upload Trusted Compute Package
    [Documentation]    SCP the installation package to the remote host.
    ${remote_pkg}=    Set Variable    ${REMOTE_HOME}/trusted-compute-installation-package.tgz
    Put File    ${TC_PACKAGE}    ${remote_pkg}    mode=0644
    ${out}=    Execute Command    ls -lh ${remote_pkg}
    Log    ${out}

Extract Package On Remote
    [Documentation]    Extract the tgz on the remote host.
    ${stdout}    ${rc}=    Execute Command
    ...    cd ${REMOTE_HOME} && tar -xzf trusted-compute-installation-package.tgz
    ...    return_stdout=True    return_rc=True
    Log    ${stdout}
    Should Be Equal As Integers    ${rc}    0    msg=tar extraction failed (rc=${rc})

Verify Docker Prerequisites On DUT
    [Documentation]    Install docker and docker compose if missing, then verify availability.
    ${docker_check_out}    ${docker_check_rc}=    Execute Command
    ...    docker --version
    ...    return_stdout=True    return_rc=True
    Log    pre-check docker --version (rc=${docker_check_rc}):\n${docker_check_out}
    ${docker_present}=    Evaluate    ${docker_check_rc} == 0

    ${compose_check_out}    ${compose_check_rc}=    Execute Command
    ...    sudo bash -lc 'docker compose version || docker-compose --version'
    ...    return_stdout=True    return_rc=True
    Log    pre-check compose version (rc=${compose_check_rc}):\n${compose_check_out}
    ${compose_present}=    Evaluate    ${compose_check_rc} == 0

    IF    not ${docker_present}
        ${update_out}    ${update_rc}=    Execute Command
        ...    sudo apt-get update -qq
        ...    return_stdout=True    return_rc=True
        Log    apt-get update for docker (rc=${update_rc}):\n${update_out}
        Should Be Equal As Integers    ${update_rc}    0    msg=apt-get update failed while preparing Docker install

        ${docker_install_out}    ${docker_install_rc}=    Execute Command
        ...    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
        ...    return_stdout=True    return_rc=True
        Log    apt-get install docker.io (rc=${docker_install_rc}):\n${docker_install_out}
        Should Be Equal As Integers    ${docker_install_rc}    0    msg=Failed to install docker.io on DUT
    END

    IF    not ${compose_present}
        ${update_out}    ${update_rc}=    Execute Command
        ...    sudo apt-get update -qq
        ...    return_stdout=True    return_rc=True
        Log    apt-get update for compose (rc=${update_rc}):\n${update_out}
        Should Be Equal As Integers    ${update_rc}    0    msg=apt-get update failed while preparing compose install

        ${compose_install_out}    ${compose_install_rc}=    Execute Command
        ...    sudo bash -lc 'set -euo pipefail; if ! DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin; then if ! DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2; then DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose; fi; fi'
        ...    return_stdout=True    return_rc=True
        Log    compose package install (rc=${compose_install_rc}):\n${compose_install_out}
        Should Be Equal As Integers    ${compose_install_rc}    0    msg=Failed to install docker compose on DUT
    END

    ${svc_out}    ${svc_rc}=    Execute Command
    ...    sudo systemctl enable --now docker
    ...    return_stdout=True    return_rc=True
    Log    systemctl enable --now docker (rc=${svc_rc}):\n${svc_out}
    Should Be Equal As Integers    ${svc_rc}    0    msg=Failed to enable/start docker service on DUT

    ${docker_verify_out}    ${docker_verify_rc}=    Execute Command
    ...    docker --version
    ...    return_stdout=True    return_rc=True
    Log    verify docker --version (rc=${docker_verify_rc}):\n${docker_verify_out}
    Should Be Equal As Integers    ${docker_verify_rc}    0    msg=docker CLI is not available on DUT

    ${compose_verify_out}    ${compose_verify_rc}=    Execute Command
    ...    sudo bash -lc 'set -euo pipefail; docker compose version || docker-compose --version'
    ...    return_stdout=True    return_rc=True
    Log    verify compose version (rc=${compose_verify_rc}):\n${compose_verify_out}
    Should Be Equal As Integers    ${compose_verify_rc}    0    msg=docker compose is not available on DUT

Install Trusted Compute In Docker Mode
    [Documentation]    Run install.sh with --docker mode.
    ${stdout}    ${rc}=    Execute Command
    ...    cd ${REMOTE_HOME}/trusted-compute-installation-package && sudo ./install.sh --docker
    ...    return_rc=True    return_stdout=True    timeout=${INSTALL_TIMEOUT}
    Log    ${stdout}
    Should Be Equal As Integers    ${rc}    0    msg=install.sh --docker failed (rc=${rc})

Verify Kata Deploy Container Is Running
    [Documentation]    Verify the kata-deploy container exists and is running.
    ${ps_out}    ${ps_rc}=    Execute Command
    ...    sudo docker ps --format '{{.Names}} {{.Status}}'
    ...    return_stdout=True    return_rc=True
    Log    ${ps_out}
    Should Be Equal As Integers    ${ps_rc}    0    msg=failed to list running docker containers
    Should Contain    ${ps_out}    kata-deploy    msg=kata-deploy container not found in running containers

Verify Sample Workload Deployment
    [Documentation]    Run nginx with Kata runtime, verify it is running and runtime is io.containerd.kata.v2.
    ${run_out}    ${run_rc}=    Execute Command
    ...    sudo docker run -d --name nginx-test --runtime io.containerd.kata.v2 nginx:1.27.0
    ...    return_stdout=True    return_rc=True
    Log    docker run nginx-test (rc=${run_rc}):\n${run_out}
    Should Be Equal As Integers    ${run_rc}    0    msg=Failed to run sample nginx workload with Kata runtime

    ${ps_out}    ${ps_rc}=    Execute Command
    ...    sudo docker ps --format '{{.Names}} {{.Status}}' | grep nginx-test
    ...    return_stdout=True    return_rc=True
    Log    verify nginx-test running (rc=${ps_rc}):\n${ps_out}
    Should Be Equal As Integers    ${ps_rc}    0    msg=nginx-test container is not running

    ${rt_out}    ${rt_rc}=    Execute Command
    ...    sudo docker inspect nginx-test --format '{{.HostConfig.Runtime}}'
    ...    return_stdout=True    return_rc=True
    Log    nginx-test runtime (rc=${rt_rc}):\n${rt_out}
    Should Be Equal As Integers    ${rt_rc}    0    msg=Failed to inspect nginx-test runtime
    ${rt}=    Strip String    ${rt_out}
    Should Be Equal    ${rt}    io.containerd.kata.v2    msg=nginx-test is not using expected Kata runtime

Verify QEMU Process Is Running On DUT
    [Documentation]    Verify at least one QEMU process is present on the DUT after trusted workload deployment.
    ${qemu_ps}=    Execute Command    ps -ef | grep -E '[q]emu-system'
    Log    ${qemu_ps}
    Should Not Be Empty    ${qemu_ps}    msg=No QEMU process found on DUT

Verify No QEMU Process Is Running On DUT
    [Documentation]    Verify no QEMU processes are present on the DUT after trusted workload cleanup.
    ${qemu_ps}=    Execute Command    ps -ef | grep -E '[q]emu-system' || true
    Log    ${qemu_ps}
    Should Be Empty    ${qemu_ps}    msg=QEMU process still running on DUT after cleanup

Cleanup Sample Workload
    [Documentation]    Stop and remove sample workload container.
    ${stop_out}    ${stop_rc}=    Execute Command
    ...    sudo docker stop nginx-test 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker stop nginx-test (rc=${stop_rc}):\n${stop_out}

    ${rm_out}    ${rm_rc}=    Execute Command
    ...    sudo docker rm nginx-test 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker rm nginx-test (rc=${rm_rc}):\n${rm_out}

Collect Docker Logs
    [Documentation]    Collect docker diagnostics from the DUT into local files.
    OperatingSystem.Create Directory    vm-logs/docker-system-logs

    ${ps_all}    ${ps_all_rc}=    Execute Command
    ...    sudo docker ps -a 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker ps -a (rc=${ps_all_rc}):\n${ps_all}
    OperatingSystem.Create File    vm-logs/docker-system-logs/docker-ps-all.log    ${ps_all}

    ${inspect}    ${inspect_rc}=    Execute Command
    ...    sudo docker inspect kata-deploy 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker inspect kata-deploy (rc=${inspect_rc}):\n${inspect}
    OperatingSystem.Create File    vm-logs/docker-system-logs/kata-deploy-inspect.json    ${inspect}

    ${logs}    ${logs_rc}=    Execute Command
    ...    sudo docker logs kata-deploy 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker logs kata-deploy (rc=${logs_rc}):\n${logs}
    OperatingSystem.Create File    vm-logs/docker-system-logs/kata-deploy.log    ${logs}

Collect DUT System Logs
    [Documentation]    Collect DUT runtime/system diagnostics for Docker trusted workload execution.
    OperatingSystem.Create Directory    vm-logs/dut-system-logs

    ${docker_journal}    ${docker_journal_rc}=    Execute Command
    ...    sudo journalctl -u docker --no-pager 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker journal (rc=${docker_journal_rc}):\n${docker_journal}
    OperatingSystem.Create File    vm-logs/dut-system-logs/docker-journal.log    ${docker_journal}

    ${containerd_journal}    ${containerd_journal_rc}=    Execute Command
    ...    sudo journalctl -u containerd --no-pager 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    containerd journal (rc=${containerd_journal_rc}):\n${containerd_journal}
    OperatingSystem.Create File    vm-logs/dut-system-logs/containerd-journal.log    ${containerd_journal}

    ${docker_info}    ${docker_info_rc}=    Execute Command
    ...    sudo docker info 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker info (rc=${docker_info_rc}):\n${docker_info}
    OperatingSystem.Create File    vm-logs/dut-system-logs/docker-info.log    ${docker_info}

    ${docker_ps}    ${docker_ps_rc}=    Execute Command
    ...    sudo docker ps -a 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    docker ps -a snapshot (rc=${docker_ps_rc}):\n${docker_ps}
    OperatingSystem.Create File    vm-logs/dut-system-logs/docker-ps-all.log    ${docker_ps}

    ${run_vc_tree}    ${run_vc_tree_rc}=    Execute Command
    ...    sudo ls -alR /run/vc 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    /run/vc tree (rc=${run_vc_tree_rc}):\n${run_vc_tree}
    OperatingSystem.Create File    vm-logs/dut-system-logs/run-vc-tree.log    ${run_vc_tree}

    ${run_vc_logs}    ${run_vc_logs_rc}=    Execute Command
    ...    sudo bash -lc 'for f in /run/vc/vm/*/console.log /run/vc/vm/*/*.log /run/vc/sbs/*/*.log /run/vc/sbs/*/*/console.log; do if [ -f "$f" ]; then echo "===== $f ====="; cat "$f"; echo; fi; done; true' 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    /run/vc sandbox logs (rc=${run_vc_logs_rc}):\n${run_vc_logs}
    OperatingSystem.Create File    vm-logs/dut-system-logs/run-vc-sandbox-logs.log    ${run_vc_logs}

    ${kata_runtime_configs}    ${kata_runtime_configs_rc}=    Execute Command
    ...    sudo bash -lc 'for f in /opt/kata/share/defaults/kata-containers/configuration*.toml /etc/kata-containers/*.toml; do if [ -f "$f" ]; then echo "===== $f ====="; cat "$f"; echo; fi; done; true' 2>&1 || true
    ...    return_stdout=True    return_rc=True
    Log    Kata runtime configs (rc=${kata_runtime_configs_rc}):\n${kata_runtime_configs}
    OperatingSystem.Create File    vm-logs/dut-system-logs/kata-runtime-configs.log    ${kata_runtime_configs}

*** Test Cases ***
TC-GS-DK-01 Upload Trusted Compute Package To DUT
    [Documentation]    Copy the Trusted Compute installation package to the DUT via SCP.
    [Tags]    golden-suite    docker    install    upload
    Upload Trusted Compute Package

TC-GS-DK-02 Extract Package On DUT
    [Documentation]    Extract the uploaded installation package on the DUT.
    [Tags]    golden-suite    docker    install    extract
    Extract Package On Remote

TC-GS-DK-03 Verify Docker Prerequisites On DUT
    [Documentation]    Ensure Docker and Docker Compose are available before installation.
    [Tags]    golden-suite    docker    validate    prerequisites
    Verify Docker Prerequisites On DUT

TC-GS-DK-04 Install Trusted Compute In Docker Mode
    [Documentation]    Run Trusted Compute installer in Docker mode.
    [Tags]    golden-suite    docker    install    trusted-compute
    Install Trusted Compute In Docker Mode

TC-GS-DK-05 Verify Kata Deploy Container Is Running
    [Documentation]    Validate kata-deploy container is running after installation.
    [Tags]    golden-suite    docker    validate
    Verify Kata Deploy Container Is Running

TC-GS-DK-06 Verify Sample Workload Deployment
    [Documentation]    Deploy sample nginx workload with Kata runtime and verify runtime mapping.
    [Tags]    golden-suite    docker    validate    trusted-workload    sample
    Verify Sample Workload Deployment
    Verify QEMU Process Is Running On DUT
    [Teardown]    Run Keywords    Cleanup Sample Workload    AND    Verify No QEMU Process Is Running On DUT

TC-GS-DK-07 Collect Docker Logs
    [Documentation]    Collect docker diagnostics for troubleshooting.
    [Tags]    golden-suite    docker    collect    logs
    Collect Docker Logs
    Collect DUT System Logs
