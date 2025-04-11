/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"reflect"
	"testing"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

// go test github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/hostinfo -v

func testSMBIOS(t *testing.T, expectedResults *model.HostInfo) {

	hostInfo := model.HostInfo{}

	smbiosInfoParser := smbiosInfoParser{}
	smbiosInfoParser.Init()
	smbiosInfoParser.Parse(&hostInfo)

	if !reflect.DeepEqual(&hostInfo, expectedResults) {
		t.Errorf("The parsed SMBIOS data does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults, hostInfo)
	}
}

func TestBmcSmbios(t *testing.T) {

	smbiosFile = "test_data/misc/smbios2"
	hostInfo := model.HostInfo{}

	smbiosInfoParser := smbiosInfoParser{}
	smbiosInfoParser.Init()

	err := smbiosInfoParser.Parse(&hostInfo)
	if err != nil {
		t.Errorf("Failed to parse SMBIOS: %v", err)
	}
}

func TestSmbiosWhitley(t *testing.T) {

	smbiosFile = "test_data/whitley/DMI"

	expectedResults := model.HostInfo{}
	expectedResults.BiosName = "Intel Corporation"
	expectedResults.BiosVersion = "WLYDCRB1.SYS.0020.P33.2012300522"
	expectedResults.HardwareUUID = "88888888-8887-1615-0115-071ba5a5a5a5"
	expectedResults.ProcessorInfo = "A6 06 06 00 FF FB EB BF"
	expectedResults.ProcessorFlags = "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE"

	testSMBIOS(t, &expectedResults)
}

func TestSmbiosPurley(t *testing.T) {

	smbiosFile = "test_data/purley/DMI"

	expectedResults := model.HostInfo{}
	expectedResults.BiosName = "Intel Corporation"
	expectedResults.BiosVersion = "SE5C620.86B.00.01.6016.032720190737"
	expectedResults.HardwareUUID = "8032632b-8fa4-e811-906e-00163566263e"
	expectedResults.ProcessorInfo = "54 06 05 00 FF FB EB BF"
	expectedResults.ProcessorFlags = "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE"

	testSMBIOS(t, &expectedResults)
}
