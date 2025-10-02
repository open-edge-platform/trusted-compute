/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type appEventLogParser struct {
	appEventFilePath string
}

// GetEventLogs reads an application event log file (tab-delimited) and returns
// a slice of PcrEventLog grouped by PCR bank+index.  The expected input format
// per line is:
//
//	<bank>\t<index>\t<tag>\t<measurement...>
//
// The implementation:
//   - validates the file exists and is not a directory
//   - uses bufio.Scanner with an increased buffer to handle long lines
//   - splits each line with SplitN(..., 4) so the measurement may contain tabs
//   - validates field count and numeric index parsing to avoid panics
//   - checks scanner.Err() after scanning to surface I/O/buffer errors
func (parser *appEventLogParser) GetEventLogs() ([]PcrEventLog, error) {
	log.Trace("eventlog/collect_application_event:GetEventLogs() Entering")
	defer log.Trace("eventlog/collect_application_event:GetEventLogs() Leaving")

	// Ensure the configured path exists and is not a directory; return wrapped error if not.
	if info, err := os.Stat(parser.appEventFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "eventlog/collect_application_event:GetEventLogs() %s file does not exist", parser.appEventFilePath)
	} else if info.IsDir() {
		return nil, errors.Errorf("eventlog/collect_application_event:GetEventLogs() path is a directory: %s", parser.appEventFilePath)
	}

	file, err := os.Open(parser.appEventFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_application_event:GetEventLogs() There was an error opening %s", parser.appEventFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("eventlog/collect_application_event:GetEventLogs() There was an error closing %s", parser.appEventFilePath)
		}
	}()

	var appEventLogs []PcrEventLog
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var tempEventData TpmEvent
		var tempAppEventLog PcrEventLog

		// Read each line of data from pcr_event_log file, parse it in array by splitting with spaces
		line := scanner.Text()
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 4 {
			return nil, errors.Errorf("eventlog/collect_application_event:getAppEventLog(): malformed line (expect 4 tab fields): %q", line)
		}

		// Parse the event log data according to:
		// part[0] sha bank
		// part[1] pcr index
		// part[2] event name
		// part[3] hash value
		tempAppEventLog.Pcr.Bank = strings.TrimSpace(parts[0])
		idx64, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return nil, errors.Wrap(err, "eventlog/collect_application_event:getAppEventLog() There was an error while converting string to integer")
		}

		index := uint32(idx64) // safe: parsed with 32-bit limit
		tempAppEventLog.Pcr.Index = uint32(index)
		tempEventData.TypeID = AppEventTypeID
		tempEventData.TypeName = AppEventName
		tempEventData.Tags = append(tempEventData.Tags, strings.TrimSpace(parts[2]))
		tempEventData.Measurement = strings.TrimSpace(parts[3])
		tempAppEventLog.TpmEvents = append(tempAppEventLog.TpmEvents, tempEventData)

		// Group entries if same pcr index and pcr bank is available in existing array
		// Otherwise create a new PcrEventLog entry and record its position.
		found := false
		for i := range appEventLogs {
			if (appEventLogs[i].Pcr.Index == tempAppEventLog.Pcr.Index) &&
				(appEventLogs[i].Pcr.Bank == tempAppEventLog.Pcr.Bank) {
				appEventLogs[i].TpmEvents = append(appEventLogs[i].TpmEvents, tempEventData)
				found = true
				break
			}
		}

		if !found {
			appEventLogs = append(appEventLogs, tempAppEventLog)
		}
	}

	// After scanning, check for any scanner error (I/O or token-too-long).
	if serr := scanner.Err(); serr != nil {
		return nil, errors.Wrap(serr, "eventlog/collect_application_event:GetEventLogs() scanning App PCR Event file error")
	}

	return appEventLogs, nil
}
