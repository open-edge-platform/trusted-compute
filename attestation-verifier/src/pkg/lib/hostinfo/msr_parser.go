/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"encoding/binary"
	"os"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

const (
	cbntMsrOffset     = 0x13A
	cbntProfile3Flags = 0x6d
	cbntProfile4Flags = 0x51
	cbntProfile5Flags = 0x7d
	cbntProfile3      = "BTGP3"
	cbntProfile4      = "BTGP4"
	cbntProfile5      = "BTGP5"
	txtMsrOffset      = 0x3A
	txtEnabledBits    = 0x3
	cbntMsrFlags      = `mk ris kfm`
)

// msrReader is an internal interfaces that supports unit tests
// abilty to mock data found in /dev/cpu/0/msr.
type msrReader interface {
	ReadAt(offset int64) (uint64, error)
}

type msrInfoParser struct {
	msrReader msrReader
}

// initialize 'msrReaderImpl' so that it can be mocked in unit tests.
func (msrInfoParser *msrInfoParser) Init() error {

	/*if _, err := os.Stat(msrFile); os.IsNotExist(err) {
		return errors.Wrapf(err, "Failed to find MSR file %q", msrFile)
	}*/

	msrInfoParser.msrReader = &msrReaderImpl{}
	return nil
}

func (msrInfoParser *msrInfoParser) Parse(hostInfo *model.HostInfo) error {

	// if the msrReader is null, then something is wrong -- abort
	// parsing and log an error
	if msrInfoParser.msrReader == nil {
		return errors.New("The MSR reader has not been initialized.")
	}

	err := msrInfoParser.parseTxt(hostInfo)
	if err != nil {
		log.Errorf("Failed to parse TXT from msr: %+v", err)
	}

	err = msrInfoParser.parseCbnt(hostInfo)
	if err != nil {
		log.Errorf("Failed to parse CBNT from msr: %+v", err)
	}

	return nil
}

func (msrInfoParser *msrInfoParser) parseTxt(hostInfo *model.HostInfo) error {

	txtFlags, err := msrInfoParser.msrReader.ReadAt(txtMsrOffset)
	if err != nil {
		//return errors.Wrap(err, "Failed to read TXT MSR flags")
		txtFlags = 0
	}

	bits, err := bitShift(txtFlags, 1, 0)
	if err != nil {
		return errors.Wrap(err, "Failed to extract TXT enabled bits")
	}

	hostInfo.HardwareFeatures.TXT = &model.HardwareFeature{Enabled: false}

	if bits == txtEnabledBits {
		hostInfo.HardwareFeatures.TXT.Enabled = true
	}

	return nil
}

func (msrInfoParser *msrInfoParser) parseCbnt(hostInfo *model.HostInfo) error {

	cbntFlags, err := msrInfoParser.msrReader.ReadAt(cbntMsrOffset)
	if err != nil {
		//return errors.Wrap(err, "Failed to read CBNT MSR flags")
		cbntFlags = 0
	}

	enabledBits, err := bitShift(cbntFlags, 32, 32)
	if err != nil {
		return errors.Wrap(err, "Failed to extract CBNT enabled flags")
	}

	hostInfo.HardwareFeatures.CBNT = &model.CBNT{}
	if enabledBits == 1 {
		hostInfo.HardwareFeatures.CBNT.Enabled = true

		profileBits, err := bitShift(cbntFlags, 7, 0)
		if err != nil {
			return errors.Wrap(err, "Failed to extract CBNT profile flags")
		}

		hostInfo.HardwareFeatures.CBNT.Meta.MSR = cbntMsrFlags

		var profileString string
		if profileBits == cbntProfile3Flags {
			profileString = cbntProfile3
		} else if profileBits == cbntProfile4Flags {
			profileString = cbntProfile4
		} else if profileBits == cbntProfile5Flags {
			profileString = cbntProfile5
		} else {
			return errors.Wrapf(err, "Unexpected CBNT profile flags %08x", profileBits)
		}

		hostInfo.HardwareFeatures.CBNT.Meta.Profile = profileString
	}

	return nil
}

//-------------------------------------------------------------------------------------------------
// Implementation of msrReader
//-------------------------------------------------------------------------------------------------
type msrReaderImpl struct{}

// ReadAt seeks to 'offset', reads 8 bytes and returns the LittleEndian
// uint64 value.
func (msrReaderImpl *msrReaderImpl) ReadAt(offset int64) (uint64, error) {

	var results uint64

	msr, err := os.Open(msrFile)
	if err != nil {
		return 0, errors.Wrapf(err, "Failed to open MSR from %q", msrFile)
	}

	defer func() {
		err = msr.Close()
		if err != nil {
			log.Errorf("Failed to close MSR file %q: %s", msrFile, err.Error())
		}
	}()

	_, err = msr.Seek(offset, 0)
	if err != nil {
		return 0, errors.Errorf("Could not seek to MSR location '%x' in file %q", offset, msrFile)
	}

	err = binary.Read(msr, binary.LittleEndian, &results)
	if err != nil {
		return 0, errors.Wrapf(err, "Failed to read results from MSR file %q", msrFile)
	}

	return results, nil
}

func bitShift(value uint64, hibit uint, lowbit uint) (uint64, error) {
	bits := hibit - lowbit + 1
	if bits > 64 {
		return 0, errors.Errorf("Invalid hi/low bit shift parameters: %x : %x", lowbit, hibit)
	}

	value >>= lowbit
	value &= (uint64(1) << bits) - 1
	return value, nil
}
