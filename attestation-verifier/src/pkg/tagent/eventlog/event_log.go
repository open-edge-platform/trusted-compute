/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
)

// PcrEventLog structure is used to hold complete events log info
type PcrEventLog struct {
	Pcr       PcrData    `json:"pcr"`
	TpmEvents []TpmEvent `json:"tpm_events"`
}

// PcrData structure is used to hold pcr info
type PcrData struct {
	Index uint32 `json:"index"`
	Bank  string `json:"bank"`
}

// TpmEvent structure is used to hold Tpm Event Info
type TpmEvent struct {
	TypeID      string   `json:"type_id"`
	TypeName    string   `json:"type_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"`
}

// EventLogParser - Public interface for collecting eventlog data
type EventLogParser interface {
	GetEventLogs() ([]PcrEventLog, error)
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

// NewEventLogParser returns an instance of EventLogFiles
func NewEventLogParser() EventLogParser {
	log.Trace("eventlog/event_log:NewEventLogParser() Entering")
	defer log.Trace("eventlog/event_log:NewEventLogParser() Leaving")

	// build an 'aggregate' event-log parser that has an array of
	// 'sub' parsers.
	eventLogParser := aggregateEventLogParser{}

	// If the Trust-Agent has been compiled with a different 'uefiEventLogFile'
	// use that to create the event-logs.  Otherwise, fall back to parsing
	// /dev/mem (default)
	var uefiParser EventLogParser
	if uefiEventLogFile != "" {
		log.Infof("Configured to use UEFI event log file %q", uefiEventLogFile)
		uefiParser = &fileEventLogParser{file: uefiEventLogFile}
	} else {
		uefiParser = &uefiEventLogParser{
			tpm2FilePath:   constants.Tpm2FilePath,
			devMemFilePath: constants.DevMemFilePath,
		}
	}
	eventLogParser.parsers = append(eventLogParser.parsers, uefiParser)

	// If the Trust-Agent has been compiled with a different 'txtEventLogFile'
	// use that to create the event-logs.  Otherwise, fall back to parsing
	// /dev/mem (default)
	var txtParser EventLogParser
	if txtEventLogFile != "" {
		log.Infof("Configured to use TXT event log file %q", txtEventLogFile)
		txtParser = &fileEventLogParser{file: txtEventLogFile}
	} else {
		txtParser = &txtEventLogParser{
			devMemFilePath:    constants.DevMemFilePath,
			txtHeapBaseOffset: TxtHeapBaseOffset,
			txtHeapSizeOffset: TxtHeapSizeOffset,
		}
	}
	eventLogParser.parsers = append(eventLogParser.parsers, txtParser)

	// always attempt to parse the application-agent events
	eventLogParser.parsers = append(eventLogParser.parsers, &appEventLogParser{
		appEventFilePath: constants.AppEventFilePath,
	})

	return &eventLogParser
}

type aggregateEventLogParser struct {
	parsers []EventLogParser
}

func (aggregateParser *aggregateEventLogParser) GetEventLogs() ([]PcrEventLog, error) {
	var eventLogs []PcrEventLog

	for _, parser := range aggregateParser.parsers {
		events, err := parser.GetEventLogs()
		if err != nil {
			log.WithError(err).Warn("eventlog/aggregateEventLogParser:GetEventLogs() Error reading event-logs")
		} else {
			eventLogs = append(eventLogs, events...)
		}
	}

	return eventLogs, nil
}
