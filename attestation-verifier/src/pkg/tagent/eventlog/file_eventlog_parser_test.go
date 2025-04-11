/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func TestTxtFile(t *testing.T) {

	fileParser := &fileEventLogParser{
		file: "../test/eventlog/txt-logs.bin",
	}

	events, err := fileParser.GetEventLogs()
	if err != nil {
		t.Fatal(err)
	}

	if events == nil || len(events) == 0 {
		t.Errorf("Failed to parse TXT event log file")
	}
}

func TestUefiFile(t *testing.T) {

	fileParser := &fileEventLogParser{
		file: "../test/eventlog/uefi_event_log.bin",
	}

	events, err := fileParser.GetEventLogs()
	if err != nil {
		t.Fatal(err)
	}

	if events == nil || len(events) == 0 {
		t.Errorf("Failed to parse UEFI event log file")
	}
}

func TestMissingFile(t *testing.T) {

	fileParser := &fileEventLogParser{
		file: "nosuchfile",
	}

	_, err := fileParser.GetEventLogs()
	if err == nil {
		t.Fatalf("Exected an error reading 'nosuchfile'")
	}

	t.Log(err)
}

func TestEmptyFile(t *testing.T) {

	fileParser := &fileEventLogParser{
		file: "../test/eventlog/empty.bin",
	}

	_, err := fileParser.GetEventLogs()
	if err == nil {
		t.Fatalf("Exected an error reading 'empty.bin'")
	}

	t.Log(err)
}

func TestNotTCGFile(t *testing.T) {

	fileParser := &fileEventLogParser{
		file: "../test/eventlog/tpm2_valid",
	}

	_, err := fileParser.GetEventLogs()
	if err == nil {
		t.Fatalf("Exected an error reading 'tpm2_valid'")
	}

	t.Log(err)
}
