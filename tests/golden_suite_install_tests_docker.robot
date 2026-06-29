*** Comments ***
SPDX-FileCopyrightText: (C) 2026 Intel Corporation
SPDX-License-Identifier: LicenseRef-Intel

*** Settings ***
Documentation    Golden Suite - Trusted Compute Docker Installation Test Suite
...              Installs the Trusted Compute package on a remote host via SSH
...              with Docker mode enabled, then validates docker-compose assets.

Library          SSHLibrary
Library          OperatingSystem

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

    ${grp_out}    ${grp_rc}=    Execute Command
    ...    sudo usermod -aG docker ${TARGET_USERNAME}
    ...    return_stdout=True    return_rc=True
    Log    usermod docker group (rc=${grp_rc}):\n${grp_out}
    Should Be Equal As Integers    ${grp_rc}    0    msg=Failed to add DUT user to docker group

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

TC-GS-DK-06 Collect Docker Logs
    [Documentation]    Collect docker diagnostics for troubleshooting.
    [Tags]    golden-suite    docker    collect    logs
    Collect Docker Logs
