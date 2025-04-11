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

func (parser *appEventLogParser) GetEventLogs() ([]PcrEventLog, error) {
	log.Trace("eventlog/collect_application_event:GetEventLogs() Entering")
	defer log.Trace("eventlog/collect_application_event:GetEventLogs() Leaving")

	if _, err := os.Stat(parser.appEventFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "eventlog/collect_application_event:GetEventLogs() %s file does not exist", parser.appEventFilePath)
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
		array := strings.Split(line, "	")
		// Parse the event log data according to sha bank, pcr index, event name, hash value
		tempAppEventLog.Pcr.Bank = array[0]
		index, err := strconv.Atoi(array[1])
		if err != nil {
			return nil, errors.Wrap(err, "eventlog/collect_application_event:getAppEventLog() There was an error while converting string to integer")
		}

		tempAppEventLog.Pcr.Index = uint32(index)
		tempEventData.TypeID = AppEventTypeID
		tempEventData.TypeName = AppEventName
		tempEventData.Tags = append(tempEventData.Tags, array[2])
		tempEventData.Measurement = array[3]
		tempAppEventLog.TpmEvents = append(tempAppEventLog.TpmEvents, tempEventData)

		// Flag is used to check if same pcr index and pcr bank is available in existing array
		flag := 0
		if appEventLogs != nil {
			for i := range appEventLogs {
				if (appEventLogs[i].Pcr.Index == tempAppEventLog.Pcr.Index) && (appEventLogs[i].Pcr.Bank == tempAppEventLog.Pcr.Bank) {
					appEventLogs[i].TpmEvents = append(appEventLogs[i].TpmEvents, tempEventData)
					flag = 1
					break
				}
			}
		}

		if flag == 0 {
			appEventLogs = append(appEventLogs, tempAppEventLog)
		}
	}

	return appEventLogs, nil
}
