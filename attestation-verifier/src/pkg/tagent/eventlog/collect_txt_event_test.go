/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_getTxtEventLog(t *testing.T) {
	type args struct {
		devMemFilePath    string
		txtHeapBaseOffset int64
		txtHeapSizeOffset int64
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
				devMemFilePath:    "../test/eventlog/txt_heap_info.bin",
				txtHeapBaseOffset: 0,
				txtHeapSizeOffset: 8,
			},
			wantErr: false,
		},
		{
			name: "Negative test: Txt event log file does not exist",
			args: args{
				devMemFilePath:    "../test/eventlog/txt_heap.bin",
				txtHeapBaseOffset: 0,
				txtHeapSizeOffset: 8,
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap base offset",
			args: args{
				devMemFilePath:    "../test/eventlog/txt_heap_info.bin",
				txtHeapBaseOffset: 1100000,
				txtHeapSizeOffset: 8,
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap size offset",
			args: args{
				devMemFilePath:    "../test/eventlog/txt_heap_info.bin",
				txtHeapBaseOffset: 0,
				txtHeapSizeOffset: 1100000,
			},
			wantErr: true,
		},
		{
			name: "Negative test: Empty bin",
			args: args{
				devMemFilePath:    "../test/eventlog/empty.bin",
				txtHeapBaseOffset: 0,
				txtHeapSizeOffset: 8,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			parser := txtEventLogParser{
				devMemFilePath:    tt.args.devMemFilePath,
				txtHeapBaseOffset: tt.args.txtHeapBaseOffset,
				txtHeapSizeOffset: tt.args.txtHeapSizeOffset,
			}

			_, err := parser.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("getTxtEventLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
