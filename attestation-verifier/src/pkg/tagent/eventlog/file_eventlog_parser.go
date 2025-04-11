/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"bytes"
	"io/ioutil"

	"github.com/pkg/errors"
)

type fileEventLogParser struct {
	file string
}

func (parser *fileEventLogParser) GetEventLogs() ([]PcrEventLog, error) {

	var eventLogs []PcrEventLog

	b, err := ioutil.ReadFile(parser.file)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read event log file %s", parser.file)
	}

	eventBuf := bytes.NewBuffer(b)

	// Parse and skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from event-log buffer
	realEventBuf, realEventSize, err := parseTcgSpecEvent(eventBuf, uint32(len(b)))
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_uefi_event:getUefiEventLog() There was an error while parsing UEFI Event Log Data")
	}

	eventLogs, err = createMeasureLog(realEventBuf, realEventSize, eventLogs, false)
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_uefi_event:getUefiEventLog() There was an error while creating measure-log data for UEFI Events")
	}

	return eventLogs, nil
}
