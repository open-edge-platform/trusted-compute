/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"fmt"
	"testing"
)

func TestDefaultEventLogs(t *testing.T) {

	// Ensure that by default, the aggregateEventLogParser contains
	// the uefi/txt parsers and the application-agent parser.
	aggregateParser := NewEventLogParser().(*aggregateEventLogParser)

	m := make(map[string]*struct{})
	for _, parser := range aggregateParser.parsers {
		m[fmt.Sprintf("%T", parser)] = &struct{}{}
	}

	parserNames := []string{
		"*eventlog.appEventLogParser",
		"*eventlog.txtEventLogParser",
		"*eventlog.uefiEventLogParser",
	}

	for _, parserName := range parserNames {
		if m[parserName] == nil {
			t.Errorf("Default EventLogParser did not contain parser %q", parserName)
		}
	}
}

func TestCustomEventLogsTXT(t *testing.T) {

	// force the use of a custom txt event log and verify it is present
	// in the 'aggregateEventLogParser'
	txtEventLogFile = "../test/eventlog/txt-logs.bin"
	aggregateParser := NewEventLogParser().(*aggregateEventLogParser)

	found := false
	for _, parser := range aggregateParser.parsers {
		if fileParser, ok := parser.(*fileEventLogParser); ok {
			if fileParser.file == txtEventLogFile {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("Specified txtEventLogFile %s but did not find it", txtEventLogFile)
	}
}

func TestCustomEventLogsUefi(t *testing.T) {

	// force the use of a custom txt event log and verify it is present
	// in the 'aggregateEventLogParser'
	uefiEventLogFile = "../test/eventlog/uefi_event_log.bin"
	aggregateParser := NewEventLogParser().(*aggregateEventLogParser)

	found := false
	for _, parser := range aggregateParser.parsers {
		if fileParser, ok := parser.(*fileEventLogParser); ok {
			if fileParser.file == uefiEventLogFile {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("Specified uefiEventLogFile %s but did not find it", uefiEventLogFile)
	}
}
