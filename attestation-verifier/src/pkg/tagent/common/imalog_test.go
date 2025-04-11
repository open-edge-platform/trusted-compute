/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"testing"
)

func TestImaPaths_getImaMeasurements(t *testing.T) {
	type fields struct {
		ProcFilePath  string
		AsciiFilePath string
	}
	tests := []struct {
		name    string
		fields  fields
		want    *ImaInfo
		wantErr bool
	}{
		{
			name: "Should fail for SHA1 algorithm not supported",
			fields: fields{
				ProcFilePath:  "../test/mockImaDir/procFilePath_Sha1",
				AsciiFilePath: "../test/mockImaDir/ascii_runtime_measurements",
			},
			wantErr: true,
		},
		{
			name: "Should pass for valid algorithm SHA256",
			fields: fields{
				ProcFilePath:  "../test/mockImaDir/procFilePath_Sha256",
				AsciiFilePath: "../test/mockImaDir/ascii_runtime_measurements",
			},
			wantErr: false,
		},
		{
			name: "Should fail for proc file does not exist",
			fields: fields{
				ProcFilePath:  "",
				AsciiFilePath: "../test/mockImaDir/ascii_runtime_measurements",
			},
			wantErr: true,
		},
		{
			name: "Should fail for ascii file does not exist",
			fields: fields{
				ProcFilePath:  "../test/mockImaDir/procFilePath_Sha256",
				AsciiFilePath: "",
			},
			wantErr: true,
		},
		{
			name: "Should fail for ima-sig template type",
			fields: fields{
				ProcFilePath:  "../test/mockImaDir/procFilePath_Sha256_ima_sig_template",
				AsciiFilePath: "../test/mockImaDir/ascii_runtime_measurements",
			},
			wantErr: true,
		},
		{
			name: "Should fail for ima template type",
			fields: fields{
				ProcFilePath:  "../test/mockImaDir/procFilePath_Sha256_ima_template",
				AsciiFilePath: "../test/mockImaDir/ascii_runtime_measurements",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imaPath := &ImaPaths{
				ProcFilePath:  tt.fields.ProcFilePath,
				AsciiFilePath: tt.fields.AsciiFilePath,
			}
			_, err := imaPath.getImaMeasurements()
			if (err != nil) != tt.wantErr {
				t.Errorf("ImaPaths.getImaMeasurements() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
