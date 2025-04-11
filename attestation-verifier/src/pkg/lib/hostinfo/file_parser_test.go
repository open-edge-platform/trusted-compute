/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"testing"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func Test_fileInfoParser_Parse(t *testing.T) {
	type args struct {
		hostInfo *model.HostInfo
	}
	tests := []struct {
		name           string
		fileInfoParser *fileInfoParser
		args           args
		wantErr        bool
	}{
		{
			name:           "Validate fileInfoParser with valid data",
			fileInfoParser: &fileInfoParser{},
			args: args{
				hostInfo: &model.HostInfo{},
			},
			wantErr: false,
		},
		{
			name:           "Validate fileInfoParser with empty hostname file",
			fileInfoParser: &fileInfoParser{},
			args: args{
				hostInfo: &model.HostInfo{},
			},
			wantErr: false,
		},
		{
			name:           "Validate fileInfoParser when Host name file not found",
			fileInfoParser: &fileInfoParser{},
			args: args{
				hostInfo: &model.HostInfo{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if tt.name == "validCase" {
			hostNameFile = "test_data/hostname"
			isDockerFile = "test_data/.dockerenv"
			isOCIContainerFile = "test_data/.container-env"
			isEFIBootFile = "test_data/efi"
		} else if tt.name == "Empty hostname file" {
			hostNameFile = "test_data/empty_hostname"
		} else if tt.name == "Host name file not found" {
			hostNameFile = "hostname"
		}
		t.Run(tt.name, func(t *testing.T) {
			fileInfoParser := &fileInfoParser{}
			if err := fileInfoParser.Parse(tt.args.hostInfo); (err != nil) != tt.wantErr {
				t.Errorf("fileInfoParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_fileInfoParser_Init(t *testing.T) {
	tests := []struct {
		name           string
		fileInfoParser *fileInfoParser
		wantErr        bool
	}{
		{
			name:           "Validate file info parser",
			fileInfoParser: &fileInfoParser{},
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileInfoParser := &fileInfoParser{}
			if err := fileInfoParser.Init(); (err != nil) != tt.wantErr {
				t.Errorf("fileInfoParser.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
