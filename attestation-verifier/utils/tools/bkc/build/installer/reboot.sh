#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


reboot_countdown=5

HOME_DIRECTORY=/opt/bkc-tool
BINARY_DIRECTORY=/opt/bkc-tool/bin
LOG_DIRECTORY=/opt/bkc-tool/log
RUN_DIRECTORY=/opt/bkc-tool/var

REBOOT_SERVICE="$HOME_DIRECTORY/bkc-reboot.service"
ALL_TEST_CTRL_FILE="$RUN_DIRECTORY/bkc_all"
REBOOT_CTRL_FILE="$RUN_DIRECTORY/reboot_cnt"

if [ ! -f $REBOOT_CTRL_FILE ]; then
	exit 0
fi

BKC_BINARY="$BINARY_DIRECTORY/bkc-tool.bin"

BKC_TEST_PREFIX="bkc-tests-"
HW_TEST_PREFIX="hardware-test-"
ATTESTATION_PREFIX="attestation-test-"

CURRENT_LOG_FILE=$RUN_DIRECTORY/bkc.log
CURRENT_FLAVOR_FILE=$RUN_DIRECTORY/flavor.json
CURRENT_CACERT_FILE=$RUN_DIRECTORY/ca.crt
CURRENT_CAKEY_FILE=$RUN_DIRECTORY/ca.key
CURRENT_MANIFEST_DIR=$RUN_DIRECTORY/host-manifest
CURRENT_REPORT_DIR=$RUN_DIRECTORY/trust-report

DIST_FLAVOR_DIR=$LOG_DIRECTORY/flavor
DIST_CACERT_DIR=$LOG_DIRECTORY/ca-cert
DIST_CAKEY_DIR=$LOG_DIRECTORY/ca-cert
DIST_MANIFEST_DIR=$LOG_DIRECTORY/host-manifest
DIST_REPORT_DIR=$LOG_DIRECTORY/report

REBOOT_LOG="$LOG_DIRECTORY/reboot.log"

detect_npw_acm() {
	which txt-stat >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		# txt-stat found
		pre_prod_str=$(txt-stat | grep pre_production | sed 's/^TB.*pre_production\: //')
		if [ $pre_prod_str == "1" ]; then
			touch $NPWACM_CTRL_FILE
		fi
	fi
	return 0
}

echo "reduce reboot count by one..." >> $REBOOT_LOG
cnt=$(cat $REBOOT_CTRL_FILE)
cnt=$(($cnt-1))
echo $cnt > $REBOOT_CTRL_FILE

# first run in reboot sequence
if [ ! -f CURRENT_FLAVOR_FILE ]; then
	echo "execute first attestation test" >> $REBOOT_LOG
	detect_npw_acm
	$BKC_BINARY attestation &>> $CURRENT_LOG_FILE
else
	echo "execute attestation test" >> $REBOOT_LOG
	$BKC_BINARY attestation -c &>> $CURRENT_LOG_FILE
	echo "bkc-tool attestation executed with return value $?" >> $REBOOT_LOG
fi

if [ $cnt -eq "0" ]; then
	echo "no more reboot required" >> $REBOOT_LOG
	echo "moving test log and files to archive directory" >> $REBOOT_LOG
	timestamp=$(date +"%Y.%m.%d-%H.%M.%S")
	mv $CURRENT_LOG_FILE $LOG_DIRECTORY/$ATTESTATION_PREFIX$timestamp
	mv $CURRENT_FLAVOR_FILE $DIST_FLAVOR_DIR/$timestamp.json
	mv $CURRENT_CACERT_FILE $DIST_CACERT_DIR/$timestamp.crt
	mv $CURRENT_CAKEY_FILE $DIST_CAKEY_DIR/$timestamp.key
	mv $CURRENT_MANIFEST_DIR/* $DIST_MANIFEST_DIR/
	mv $CURRENT_REPORT_DIR/* $DIST_REPORT_DIR/
	echo "test log and files moved to archive directory" >> $REBOOT_LOG
	# if bkc_all exists, concat latest hardware log with attestation log
	if [ -f $ALL_TEST_CTRL_FILE ]; then
		echo "executing from bkc-tool without argument, concating logs" >> $REBOOT_LOG
		out_file="$LOG_DIRECTORY/$BKC_TEST_PREFIX$timestamp"
		hw_test_log=$(ls -tr $LOG_DIRECTORY/$HW_TEST_PREFIX* | tail -1)
		attest_test_log=$LOG_DIRECTORY/$ATTESTATION_PREFIX$timestamp
		cat $hw_test_log > $out_file
		cat $attest_test_log >> $out_file
		echo "logs concatinated" >> $REBOOT_LOG
		rm -rf $ALL_TEST_CTRL_FILE
	fi
	echo "clean up run directory..." >> $REBOOT_LOG
	rm -f CURRENT_FLAVOR_FILE=$RUN_DIRECTORY/flavor.json
	rm -f CURRENT_CACERT_FILE=$RUN_DIRECTORY/ca.crt
	rm -f CURRENT_CAKEY_FILE=$RUN_DIRECTORY/ca.key
	rm -rf CURRENT_MANIFEST_DIR=$RUN_DIRECTORY/host-manifest
	rm -rf CURRENT_REPORT_DIR=$RUN_DIRECTORY/trust-report
	# just for safety reason
	echo "disable service after 5 seconds" >> $REBOOT_LOG
	sleep 5
	# disable reboot service
	systemctl disable $REBOOT_SERVICE >/dev/null 2>&1
	exit 0
fi
echo "$reboot_countdown seconds to reboot" >> $REBOOT_LOG
sleep $reboot_countdown
echo "rebooting..." >> $REBOOT_LOG
sleep 1
reboot
