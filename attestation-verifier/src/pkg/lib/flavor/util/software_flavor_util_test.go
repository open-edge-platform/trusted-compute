/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func TestSoftwareFlavorUtil_GetSoftware(t *testing.T) {
	type args struct {
		measurements taModel.Measurement
	}
	var softwareflvr hvs.Software
	err := json.Unmarshal([]byte(softwareFlavor), &softwareflvr)
	if err != nil {
		log.Error("Error in unmarshalling json", err)
	}
	tests := []struct {
		name string
		sfu  SoftwareFlavorUtil
		args args
		want hvs.Software
	}{
		{
			name: "Get software flavor",
			args: args{
				measurements: taModel.Measurement{
					File:    []taModel.FileMeasurementType{taModel.FileMeasurementType{Path: "test_data/resources/test.json"}},
					Dir:     []taModel.DirectoryMeasurementType{taModel.DirectoryMeasurementType{Path: "test_data/resources"}},
					Symlink: []taModel.SymlinkMeasurementType{taModel.SymlinkMeasurementType{Path: "test_data/resources"}},
				},
			},
			want: softwareflvr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sfu := SoftwareFlavorUtil{}
			if got := sfu.GetSoftware(tt.args.measurements); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftwareFlavorUtil.GetSoftware() = %v, want %v", got, tt.want)
			}
		})
	}
}

var softwareFlavor = `{"measurements":{"est_data-resources":{"type":"symlinkMeasurementType","value":"","Path":"test_data/resources"},"est_data-resources-test.json":{"type":"fileMeasurementType","value":"","Path":"test_data/resources/test.json"}}}`
