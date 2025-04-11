/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_getUefiEventLog(t *testing.T) {
	type args struct {
		tpm2FilePath   string
		devMemFilePath string
	}
	tests := []struct {
		name    string
		args    args
		want    []PcrEventLog
		wantErr bool
	}{
		{
			name: "Positive test case",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_valid",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Invalid Offset",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_invalid_address",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: TPM2 file has invalid file length",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_invalid_file_length",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: TPM2 file has invalid signature",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_invalid_signature",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: File Not exist",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_not_exist",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Empty TPM2",
			args: args{
				tpm2FilePath:   "../test/eventlog/empty.bin",
				devMemFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Empty EventLogFile",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_valid",
				devMemFilePath: "../test/eventlog/empty.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Empty EventLogFile",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_valid",
				devMemFilePath: "../test/eventlog/eventlog_not_exist.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Empty EventLogFile",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_valid1",
				devMemFilePath: "../test/eventlog/incomplete_tcg_spec_event.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: EventLogFile Invalid",
			args: args{
				tpm2FilePath:   "../test/eventlog/tpm2_valid",
				devMemFilePath: "../test/eventlog/uefi_event_log_invalid.bin",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			parser := uefiEventLogParser{
				tpm2FilePath:   tt.args.tpm2FilePath,
				devMemFilePath: tt.args.devMemFilePath,
			}

			_, err := parser.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("getUefiEventLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
