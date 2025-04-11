/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_getAppEventLog(t *testing.T) {
	type args struct {
		appEventFilePath string
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
				appEventFilePath: "../test/eventlog/pcr_event_log",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Pcr event log file does not exist",
			args: args{
				appEventFilePath: "../test/eventlog/pcr_event",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := appEventLogParser{
				appEventFilePath: tt.args.appEventFilePath,
			}

			_, err := parser.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("appEventLogParser.GetEventLogs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
