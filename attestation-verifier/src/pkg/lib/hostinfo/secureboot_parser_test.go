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

func testSecureBootParser(t *testing.T, expectedResults *model.HostInfo) {
	hostInfo := model.HostInfo{}

	secureBootParser := secureBootParser{}

	secureBootParser.Parse(&hostInfo)

	if !reflect.DeepEqual(hostInfo.HardwareFeatures.UEFI, expectedResults.HardwareFeatures.UEFI) {
		t.Errorf("The parsed UEFI data does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults.HardwareFeatures.UEFI, hostInfo.HardwareFeatures.UEFI)
	}
}

func TestSecureBootWhitley(t *testing.T) {

	secureBootFile = "test_data/whitley/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.UEFI = &model.UEFI{}
	expectedResults.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false

	testSecureBootParser(t, &expectedResults)
}

func TestSecureBootPurley(t *testing.T) {

	// purley doesn't have efi var files -- provide a non-existent path
	secureBootFile = "test_data/purley/nosuchfile"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.UEFI = &model.UEFI{}
	expectedResults.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false

	testSecureBootParser(t, &expectedResults)
}

func TestSecureBootShortFile(t *testing.T) {

	// test a file that doesn't have enough data -- it not error and
	// show secure-boot as disabled
	secureBootFile = "test_data/misc/SecureBootShortFile"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.UEFI = &model.UEFI{}
	expectedResults.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false

	testSecureBootParser(t, &expectedResults)
}

func TestSecureBootZeroFile(t *testing.T) {

	// test a file that has zeros (secure boot is not enabled)
	secureBootFile = "test_data/misc/SecureBootZeroFile"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.UEFI = &model.UEFI{}
	expectedResults.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false

	testSecureBootParser(t, &expectedResults)

}

func Test_secureBootParser_Init(t *testing.T) {
	tests := []struct {
		name             string
		secureBootParser *secureBootParser
		wantErr          bool
	}{
		{
			name:             "Validate secureBootParser with valid data",
			secureBootParser: &secureBootParser{},
			wantErr:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secureBootParser := &secureBootParser{}
			if err := secureBootParser.Init(); (err != nil) != tt.wantErr {
				t.Errorf("secureBootParser.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
