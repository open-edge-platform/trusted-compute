#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


HOME_DIRECTORY=/opt/bkc-tool
BINARY_DIRECTORY=/opt/bkc-tool/bin
SOFT_LINK=/usr/bin/bkc-tool
LOG_DIRECTORY=/opt/bkc-tool/log
RUN_DIRECTORY=/opt/bkc-tool/var

BKC_BINARY="$BINARY_DIRECTORY/bkc-tool.bin"
REBOOT_SCRIPT="$BINARY_DIRECTORY/reboot.sh"
REBOOT_SERVICE="$HOME_DIRECTORY/bkc-reboot.service"
ALL_TEST_CTRL_FILE="$RUN_DIRECTORY/bkc_all"
REBOOT_CTRL_FILE="$RUN_DIRECTORY/reboot_cnt"
CURRENT_LOG_FILE="$RUN_DIRECTORY/bkc.log"

HW_TEST_PREFIX="hardware-test-"
ATTESTATION_PREFIX="attestation-test-"

REBOOT_COUNTDOWN=10
REBOOT_COUNT=2

uninstall() {
    rm -f $BINARY_DIRECTORY/*
    rm -f $SOFT_LINK
    if [ "$1" == "--purge" ] ; then
        rm -rf $HOME_DIRECTORY
    fi
}

hw_tests() {
    ts=$(date '+%Y.%m.%d-%H.%M.%S')
    output="$LOG_DIRECTORY/$HW_TEST_PREFIX$ts"
    $BKC_BINARY platform-info --trusted-boot &> $output
    if [ $? -eq 1 ]; then
        echo "Warning: failed to check trusted boot configuration"
    fi
    $BKC_BINARY platform-info &>> $output
    if [ $? -ne 0 ]; then
        echo "Warning: failed to check platform info"
    fi
    $BKC_BINARY tpm-provider &>> $output
    if [ $? -ne 0 ]; then
        echo "Warning: failed to check tpm"
    fi
    # remove unwanted error message
    sed -i '/create_primary_handle.c/d' $output
}

set_reboot() {
    # clean up reboot_cnt if input is not valid integer
    if [[ $1 =~ ^-?[0-9]+$ ]]; then
        echo $1 > $REBOOT_CTRL_FILE
    else
        rm -rf $REBOOT_CTRL_FILE
        return 1
    fi
    # patch bkc-reboot.service file if needed
    if [[ $2 =~ ^-?[0-9]+$ ]]; then
        sed -i "s/reboot_countdown=.*/reboot_countdown=$2/" $REBOOT_SCRIPT
    fi
    # un-comment this line to dump reboot log to file at /opt/bkc-tool/log/reboot.log
    # sed -i "s/reboot_log=.*/reboot_log=true/" $REBOOT_SCRIPT
    systemctl disable $REBOOT_SERVICE >/dev/null 2>&1
    systemctl enable $REBOOT_SERVICE
    systemctl daemon-reload
}

cleanup_aborted_tests() {
	echo "cleaning up previously aborted test sequence"
	echo "moving test log and files to archive directory"
	timestamp=$(date +"%Y.%m.%d-%H.%M.%S")
	mv $CURRENT_LOG_FILE $LOG_DIRECTORY/$ATTESTATION_PREFIX$timestamp
	mv $CURRENT_FLAVOR_FILE $DIST_FLAVOR_DIR/$timestamp.json
	mv $CURRENT_CACERT_FILE $DIST_CACERT_DIR/$timestamp.crt
	mv $CURRENT_CAKEY_FILE $DIST_CAKEY_DIR/$timestamp.key
	mv $CURRENT_MANIFEST_DIR/* $DIST_MANIFEST_DIR/
	mv $CURRENT_REPORT_DIR/* $DIST_REPORT_DIR/
	echo "test log and files moved to archive directory"
	# if bkc_all exists, concat latest hardware log with attestation log
	if [ -f $ALL_TEST_CTRL_FILE ]; then
		echo "executed from bkc-tool without argument, concating logs"
		out_file="$LOG_DIRECTORY/$BKC_TEST_PREFIX$timestamp"
		hw_test_log=$(ls -tr $LOG_DIRECTORY/$HW_TEST_PREFIX* | tail -1)
		attest_test_log=$LOG_DIRECTORY/$ATTESTATION_PREFIX$timestamp
		cat $hw_test_log > $out_file
		cat $attest_test_log >> $out_file
		echo "logs concatinated"
		rm -rf $ALL_TEST_CTRL_FILE
	fi
	rm -f CURRENT_FLAVOR_FILE=$RUN_DIRECTORY/flavor.json
	rm -f CURRENT_CACERT_FILE=$RUN_DIRECTORY/ca.crt
	rm -f CURRENT_CAKEY_FILE=$RUN_DIRECTORY/ca.key
	rm -rf CURRENT_MANIFEST_DIR=$RUN_DIRECTORY/host-manifest
	rm -rf CURRENT_REPORT_DIR=$RUN_DIRECTORY/trust-report
	# just for safety reason
	sleep 1
	# disable reboot service
	systemctl disable $REBOOT_SERVICE >/dev/null 2>&1
}

attestation() {
    $BKC_BINARY platform-info --trusted-boot &> $CURRENT_LOG_FILE
    local cmd_ret=$?
    if [ $cmd_ret -ne 0 ]; then
        if [ $cmd_ret -eq 1 ] ; then
            echo "Error: failed to check trusted boot validity, skipping attestation tests"
            return 1
        else
            echo "Warning: invalid trusted boot configuration, skipping attestation tests" | tee -a $CURRENT_LOG_FILE
            return 1
        fi
    fi
    set_reboot $REBOOT_COUNT $REBOOT_COUNTDOWN
    if [ $? -ne 0 ]; then
        echo "Error: failed to configure reboot service"
        return 1
    fi
    echo "$REBOOT_COUNTDOWN seconds to reboot"
    while [ $REBOOT_COUNTDOWN -gt 0 ]; do
        printf "$REBOOT_COUNTDOWN "
        REBOOT_COUNTDOWN=$(($REBOOT_COUNTDOWN-1))
        sleep 1
    done
    echo ""
    echo "rebooting..."
    sleep 1
    reboot
}

print_help() {
    echo "Usage: $0"
    echo "  Executes hardware tests and one attestion test followed by another after reboot"
    echo ""
    echo "Usage: $0 <command> [flags]"
    echo "  Commands:"
    echo "    help|-h|--help            print help and exit"
    echo "    version                   print version and exit"
    echo "    platform-info             get platform information of host"
    echo "    tpm-provider              execute TPM related tests"
    echo "    hardware-test             execute hardware tests"
    echo "    attestation               execute attestation test"
    echo "      -r <integer>              reboot count"
    echo "      -c <integer>              reboot countdown timer in seconds"
    echo "      -n                        clean up previously aborted test sequence"
    echo "    uninstall                 remove bkc binaries"
    echo "      --purge                   remove saved test logs and attestation files"
}

# bkc-tool
# it runs both tests with default settings
if [ $# -eq 0 ]; then
    # run tests
    hw_tests
    touch $ALL_TEST_CTRL_FILE
    attestation
    # if attestation return without a reboot, there is something wrong
    exit 1
fi

# bkc-tool -h|help|--help
if [ "$1" == -h ] || [ "$1" == "help" ] || [ "$1" == "--help" ]; then
    print_help
    exit 0
fi

# bkc-tool version
if [ "$1" == "version" ]; then
    $BKC_BINARY version
    exit 0
fi

# bkc-tool hardware-test
if [ "$1" == "hardware-test" ]; then
    hw_tests
    exit $?
fi

# bkc-tool platform-info
if [ "$1" == "platform-info" ]; then
    $BKC_BINARY platform-info
    exit 0
fi

# bkc-tool tpm-provider
if [ "$1" == "tpm-provider" ]; then
    $BKC_BINARY tpm-provider
    exit 0
fi

# bkc-tool uninstall
if [ "$1" == "uninstall" ]; then
    uninstall $2
    exit 0
fi

# print help if the command is not
# bkc-tool attestation
if [ "$1" != "attestation" ]; then
    print_help
    exit 1
fi

cleanup_test=false
OPTIND=2
while getopts r:c:n opt; do
    case ${opt} in
    c)  if [ ! -z ${OPTARG} ]; then
            REBOOT_COUNTDOWN=${OPTARG}
            echo "Info: reboot countdown set to \"$REBOOT_COUNTDOWN\""
        fi ;;
    r)  if [ ! -z ${OPTARG} ]; then
            REBOOT_COUNT=${OPTARG}
            echo "Info: reboot count set to \"$REBOOT_COUNT\""
        fi ;;
    n)  cleanup_test=true ;;
    *)  print_help; exit 1 ;;
    esac
done

if [ "$cleanup_test" == "true" ]; then
    cleanup_aborted_tests
fi

attestation