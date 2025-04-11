/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func testOsInfoParser(t *testing.T, osInfoParser *osInfoParser, expectedResults *model.HostInfo) {
	hostInfo := model.HostInfo{}

	osInfoParser.Parse(&hostInfo)

	if !reflect.DeepEqual(&hostInfo, expectedResults) {
		t.Errorf("The parsed OS data does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults, hostInfo)
	}
}

func TestOsInfoPurley(t *testing.T) {

	// initialize an osInfoParser using file data from a purley system
	osReleaseFile = "test_data/purley/os-release"
	osInfoParser := osInfoParser{}
	osInfoParser.Init()

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "RedHatEnterprise"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &osInfoParser, &expectedResults)
}

func TestOsInfoWhitley(t *testing.T) {

	// initialize an osInfoParser using file data from a whitley system
	osReleaseFile = "test_data/whitley/os-release"
	osInfoParser := osInfoParser{}
	osInfoParser.Init()

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "RedHatEnterprise"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &osInfoParser, &expectedResults)
}

func TestOsInfoBadLineNoEquals(t *testing.T) {

	data := []byte(`NAME="Red Hat Enterprise Linux"
	THIS_IS_A_BAD_LINE_WITHOUT_EQUALS_BUT_SHOULD_STILL_WORK
	VERSION_ID="8.1"
	`)

	osInfoParser := osInfoParser{
		reader: ioutil.NopCloser(bytes.NewReader(data)),
	}

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "RedHatEnterprise"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &osInfoParser, &expectedResults)
}

func TestOsInfoBadLineMultipleEquals(t *testing.T) {

	data := []byte(`NAME="Red Hat Enterprise Linux"
	WHAT=Yes=No
	VERSION_ID="8.1"
	`)

	osInfoParser := osInfoParser{
		reader: ioutil.NopCloser(bytes.NewReader(data)),
	}

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "RedHatEnterprise"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &osInfoParser, &expectedResults)
}
