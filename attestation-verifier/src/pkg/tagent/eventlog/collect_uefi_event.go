/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"

	"github.com/pkg/errors"
)

type uefiEventLogParser struct {
	tpm2FilePath   string
	devMemFilePath string
}

func (parser *uefiEventLogParser) GetEventLogs() ([]PcrEventLog, error) {
	log.Trace("eventlog/collect_uefi_event:getUefiEventLog() Entering")
	defer log.Trace("eventlog/collect_uefi_event:getUefiEventLog() Leaving")

	tpm2Sig := make([]byte, Uint32Size)
	tpm2len := make([]byte, Uint32Size)
	uefiEventAddr := make([]byte, Uint64Size)
	uefiEventSize := make([]byte, Uint32Size)
	if _, err := os.Stat(parser.tpm2FilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() %s file does not exist", parser.tpm2FilePath)
	}

	file, err := os.Open(parser.tpm2FilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error opening %s", parser.tpm2FilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Warnf("eventlog/collect_uefi_event:GetEventLogs() There was an error closing %s", parser.tpm2FilePath)
		}
	}()

	// Validate TPM2 file signature
	_, err = io.ReadFull(file, tpm2Sig)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error reading TPM2 Signature from %s", parser.tpm2FilePath)
	}

	tpm2Signature := string(tpm2Sig)
	if Tpm2Signature != tpm2Signature {
		return nil, errors.Errorf("eventlog/collect_uefi_event:GetEventLogs() Invalid TPM2 Signature in %s", parser.tpm2FilePath)
	}

	// Validate TPM2 file length
	_, err = io.ReadFull(file, tpm2len)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error reading TPM2 File Length from %s", parser.tpm2FilePath)
	}

	tpm2FileLength := binary.LittleEndian.Uint32(tpm2len)
	if tpm2FileLength < Tpm2FileLength {
		return nil, errors.Errorf("eventlog/collect_uefi_event:GetEventLogs() UEFI Event Info missing in %s", parser.tpm2FilePath)
	}

	_, err = file.Seek(UefiBaseOffset, io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error traversing %s for UEFI Event Base Offset", parser.tpm2FilePath)
	}

	_, err = io.ReadFull(file, uefiEventAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error reading UEFI Event Address from %s", parser.tpm2FilePath)
	}

	_, err = file.Seek(UefiSizeOffset, io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error traversing %s for UEFI Event Size Offset", parser.tpm2FilePath)
	}

	_, err = io.ReadFull(file, uefiEventSize)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error reading UEFI Event Size from %s", parser.tpm2FilePath)
	}

	uefiEventSizeLE := binary.LittleEndian.Uint32(uefiEventSize)
	uefiEventAddrLE := binary.LittleEndian.Uint64(uefiEventAddr)

	uefiEventBuf, err := readUefiEvent(parser.devMemFilePath, uefiEventSizeLE, uefiEventAddrLE)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:getUefiEventLog() There was an error reading UEFI Event Log from %s", parser.devMemFilePath)
	}

	// Parse and skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from event-log buffer
	realUefiEventBuf, realUefiEventSize, err := parseTcgSpecEvent(uefiEventBuf, uefiEventSizeLE)
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error while parsing UEFI Event Log Data")
	}

	var uefiEventLogs []PcrEventLog
	uefiEventLogs, err = createMeasureLog(realUefiEventBuf, realUefiEventSize, uefiEventLogs, false)
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_uefi_event:GetEventLogs() There was an error while creating measure-log data for UEFI Events")
	}

	return uefiEventLogs, nil
}

// ReadUefiEvent - Function to read Uefi Event binary data from /dev/mem
func readUefiEvent(devMemFilePath string, uefiEventSize uint32, uefiEventAddr uint64) (*bytes.Buffer, error) {
	log.Trace("eventlog/collect_uefi_event:readUefiEvent() Entering")
	defer log.Trace("eventlog/collect_uefi_event:readUefiEvent() Leaving")

	eventLogBuffer := make([]byte, uefiEventSize)
	if _, err := os.Stat(devMemFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:readUefiEvent() %s file does not exist", devMemFilePath)
	}

	file, err := os.Open(devMemFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:readUefiEvent() There was an error opening %s", devMemFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Warnf("eventlog/collect_uefi_event:readUefiEvent() There was an error closing %s", devMemFilePath)
		}
	}()

	// Go to Uefi Event Log Address in /dev/mem
	_, err = file.Seek(int64(uefiEventAddr), io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:readUefiEvent() There was an error traversing %s for UEFI Event Address", devMemFilePath)
	}

	_, err = io.ReadFull(file, eventLogBuffer)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_uefi_event:readUefiEvent() There was an error reading UEFI Event Log from %s", devMemFilePath)
	}

	buf := bytes.NewBuffer(eventLogBuffer)
	return buf, nil
}
