/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strings"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

var cpuFlags = []string{
	"FPU", /* 0 */
	"VME",
	"DE",
	"PSE",
	"TSC",
	"MSR",
	"PAE",
	"MCE",
	"CX8",
	"APIC",
	"", /* 10 */
	"SEP",
	"MTRR",
	"PGE",
	"MCA",
	"CMOV",
	"PAT",
	"PSE-36",
	"PSN",
	"CLFSH",
	"", /* 20 */
	"DS",
	"ACPI",
	"MMX",
	"FXSR",
	"SSE",
	"SSE2",
	"SS",
	"HTT",
	"TM",
	"",    /* 30 */
	"PBE", /* 31 */
}

const (
	sizeOfHeader    = 4   // SMBIOS header is uint8 + uint8 + uint16
	terminatingType = 127 // SMBIOS terminating header/type value
	constUefiFlag   = 0x8 // See SMBIOS Spec section 7.1.2.2
)

// smbiosInfoParser reads data from 'smbiosFile' and uses the data to populate
// a 'HostInfo' structure (passed in Parse).  See https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf
type smbiosInfoParser struct{}

type smbiosTable struct {
	Data    []byte
	Strings []string
}

func (smbiosInfoParser *smbiosInfoParser) Init() error {
	return nil
}

func (smbiosInfoParser *smbiosInfoParser) Parse(hostInfo *model.HostInfo) error {

	var err error

	if _, err := os.Stat(smbiosFile); os.IsNotExist(err) {
		return errors.Errorf("Could not find SMBIOS file %q", smbiosFile)
	}

	file, err := os.Open(smbiosFile)
	if err != nil {
		errors.Wrapf(err, "Could not open SMBIOS file %q", smbiosFile)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Errorf("Failed close SMBIOS file: %s", err.Error())
		}
	}()

	for {
		table, err := smbiosInfoParser.parseNextTable(file)
		if err != nil {
			return err
		}

		log.Tracef("Loaded SMBIOS table type %d\n", table.Type())

		if readerFunc, ok := readers[table.Type()]; ok {
			err = readerFunc(table, hostInfo)
			if err != nil {
				return err
			}
		}

		if table.Type() == terminatingType {
			break
		}
	}

	return nil
}

func (smbiosInfoParser *smbiosInfoParser) parseNextTable(file *os.File) (*smbiosTable, error) {

	table := smbiosTable{}

	// get the current position in the table for error messages/debugging
	off, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// Attempt to make "Data" have the similar layout as the DMTF/SMBIOS spec.
	// The tables always starts with the type/length/handle.  So,
	// allocate a buffer and copy those values into it.  Perhaps redundant
	// but perhaps makes the code more readable (ex. where getDWORD(7)
	// aligns with the tables in the spec -- not getDWORD(3) due to the missing
	// entries).
	header := make([]byte, 4)
	file.Read(header)
	length := header[1]

	writer := &bytes.Buffer{}
	writer.Write(header)
	_, err = io.CopyN(writer, file, int64(length-4))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to copy Data with length 0x%x from SMBIOS table at 0x%x", length-4, off)
	}

	table.Data = writer.Bytes()

	//
	// Parse strings
	//
	table.Strings = []string{}
	var stringBuilder strings.Builder
	var char byte

	// read the first byte of the string section (so we can check for empty)
	err = binary.Read(file, binary.LittleEndian, &char)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read leading byte of strings section from SMBIOS table at 0x%x", off)
	}

	for {

		if char == 0 {
			// Encountered a terminator.  Look for the second terminator that ends the
			// strings section.
			err = binary.Read(file, binary.LittleEndian, &char)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to read the second terminating byte of strings section from SMBIOS table at 0x%x", off)
			}

			if char == 0 {
				break // end of table -- continue with next entry
			}
		}

		// not terminated, add the character to the string
		stringBuilder.WriteByte(char)

		// continue to read bytes until terminated
		for {
			err = binary.Read(file, binary.LittleEndian, &char)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to string byte from SMBIOS table at 0x%x", off)
			}

			if char == 0 {
				// done with a string, add it to the table and continue
				table.Strings = append(table.Strings, stringBuilder.String())
				stringBuilder.Reset()
				break
			} else {
				stringBuilder.WriteByte(char)
			}
		}
	}

	return &table, nil
}

var readers = map[uint8]func(*smbiosTable, *model.HostInfo) error{
	0x0: func(table *smbiosTable, hostInfo *model.HostInfo) error {

		// see SMBIOS Table 7.1
		var err error

		// "Vendor" at 4h
		hostInfo.BiosName, err = table.getString(4)
		if err != nil {
			return errors.Wrap(err, "Could not read BiosName")
		}

		if strings.TrimSpace(hostInfo.BiosName) == "" {
			// If the BIOS name is empty, log a warning and assign a default value.
			// This is a work around for single node attestation to functional
			log.Warnf("BIOS name is empty, assigning default value")
			hostInfo.BiosName = "no-name-bios"
		}

		// "BiosVersion" at 5h
		hostInfo.BiosVersion, err = table.getString(5)
		if err != nil {
			return errors.Wrap(err, "Could not read BiosVersion")
		}

		if strings.TrimSpace(hostInfo.BiosVersion) == "" {
			// If the BIOS version is empty, log a warning and assign a default value.
			// This is a work around for single node attestation to functional
			log.Warnf("BIOS version is empty, assigning default value")
			hostInfo.BiosVersion = "no-bios-version"
		}

		return nil
	},
	0x1: func(table *smbiosTable, hostInfo *model.HostInfo) error {

		// See SMBIOS Table 7.2

		// The hardware-uuid is at offset 8 and is 16 bytes long, make sure we at least have
		// that much data
		if len(table.Data) < 24 {
			return errors.Errorf("The Data size was to small (0x%x) to parse the SMBIOS hardware-uuid", len(table.Data))
		}

		// Custom parsing of the uuid -- couldn't use uuid package due to byte order.
		//
		// Section 7.2.1 from https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf
		//
		// The UUID {00112233-4455-6677-8899-AABBCCDDEEFF} would thus be represented as:
		//   33 22 11 00 - 55 44 - 77 66 - 88 99 - AA BB CC DD EE FF
		//
		// The UUID starts at offset 4 (bytes 4-20)
		//
		// TODO: Handle conditions where UUID is  all FF or all 00 (not set) -- see SMBIOS spec
		uuid := table.Data[8:24]
		hostInfo.HardwareUUID = ""
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[3:4])
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[2:3])
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[1:2])
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[0:1])
		hostInfo.HardwareUUID += "-"
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[5:6])
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[4:5])
		hostInfo.HardwareUUID += "-"
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[7:8])
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[6:7])
		hostInfo.HardwareUUID += "-"
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[8:10])
		hostInfo.HardwareUUID += "-"
		hostInfo.HardwareUUID += hex.EncodeToString(uuid[10:16])

		// // TODO:  Add "Serial Number" to hostinfo at 7h
		// serialNumber, err := table.getString(7)
		// if err != nil {
		// 	return errors.Wrapf(err, "Could not read Serial Number")
		// }

		// fmt.Println(serialNumber)

		return nil
	},
	0x4: func(table *smbiosTable, hostInfo *model.HostInfo) error {

		// See SMBIOS Table 7.5

		// Make sure there is enough data for this function
		if len(table.Data) < 16 {
			return errors.Errorf("The Data size was to small (0x%x) to parse the SMBIOS process-info", len(table.Data))
		}

		// Each of the SMBIOS files in the test directory contain two Type 4
		// entries.  The first appears to be relevant to host-info and the second
		// is not (i.e., determined by comparing the output of dmicode).  The second entry
		// has the 6h offest of zero (no processor family).  For now, use that
		// to avoid assigning the ProcessorInfo the wrong value.
		if table.Data[6] > 0 {
			processorID := ""

			// https://github.com/mirror/dmidecode/blob/a4b31b2bc537f8703c9bfeff1d5604f6e5684db5/dmidecode.c#L1090
			for i := 8; i < 16; i++ {
				processorID += hex.EncodeToString(table.Data[i : i+1])
				processorID += " "
			}

			hostInfo.ProcessorInfo = strings.TrimSpace(strings.ToUpper(processorID))

			// https://github.com/mirror/dmidecode/blob/a4b31b2bc537f8703c9bfeff1d5604f6e5684db5/dmidecode.c#L1217
			processorFlags := ""
			edx, err := table.getQWORD(12)
			if err != nil {
				return errors.Wrap(err, "Could not read EDX value")
			}

			for i, flag := range cpuFlags {
				if len(flag) != 0 && (edx&(1<<i)) != 0 {
					processorFlags += flag + " "
				}
			}

			hostInfo.ProcessorFlags = strings.TrimSpace(strings.ToUpper(processorFlags))
		}

		return nil
	},
}

func (table *smbiosTable) getBYTE(off int) (byte, error) {
	if len(table.Data) < off+1 {
		return 0, errors.Errorf("Could not get BYTE, the offset '%x' exceeded the length of the SMBIOS data", off)
	}

	return table.Data[off], nil
}

func (table *smbiosTable) getQWORD(off int) (uint64, error) {
	if len(table.Data) < off+8 {
		return 0, errors.Errorf("Could not get QWORD, the offset '%x' exceeded the length of the SMBIOS data", off)
	}

	return binary.LittleEndian.Uint64(table.Data[off : off+8]), nil
}

func (table *smbiosTable) getString(off int) (string, error) {
	b, err := table.getBYTE(off)
	if err != nil {
		return "", err
	}

	// the string references start at 1, convert to zero index (i.e., -1)
	if len(table.Strings) < int(b-1) {
		return "", errors.Errorf("Table index '%x' had  invalid string index '%x'", off, b)
	}

	return table.Strings[b-1], nil
}

func (table *smbiosTable) Type() byte {
	return table.Data[0]
}

func (table *smbiosTable) Length() byte {
	return table.Data[1]
}

func (table *smbiosTable) Handle() uint16 {
	return binary.LittleEndian.Uint16(table.Data[2:4])
}
