/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"testing"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func Test_miscInfoParser_Parse(t *testing.T) {
	type args struct {
		hostInfo *model.HostInfo
	}
	tests := []struct {
		name           string
		miscInfoParser *miscInfoParser
		args           args
		wantErr        bool
	}{
		{
			name:           "Validate miscInfoParser with valid data",
			miscInfoParser: &miscInfoParser{},
			args: args{
				hostInfo: &model.HostInfo{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscInfoParser := &miscInfoParser{}
			if err := miscInfoParser.Parse(tt.args.hostInfo); (err != nil) != tt.wantErr {
				t.Errorf("miscInfoParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_miscInfoParser_Init(t *testing.T) {
	tests := []struct {
		name           string
		miscInfoParser *miscInfoParser
		wantErr        bool
	}{
		{
			name:           "Validate miscInfoParser init with valid data",
			miscInfoParser: &miscInfoParser{},
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscInfoParser := &miscInfoParser{}
			if err := miscInfoParser.Init(); (err != nil) != tt.wantErr {
				t.Errorf("miscInfoParser.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
