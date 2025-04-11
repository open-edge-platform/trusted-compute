/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"bytes"
	"testing"
)

func Test_printToWriter(t *testing.T) {
	type args struct {
		cmdName string
		msg     string
	}
	tests := []struct {
		name  string
		args  args
		wantW string
	}{
		{
			name: "Validate print to writer",
			args: args{
				cmdName: "ls",
				msg:     "list",
			},
			wantW: "ls: list\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			printToWriter(w, tt.args.cmdName, tt.args.msg)
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("printToWriter() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestPrefixUnderscroll(t *testing.T) {
	type args struct {
		e string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Validate prefix under scroll",
			args: args{
				e: "Test-string",
			},
			want: "TEST_STRING_",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrefixUnderscroll(tt.args.e); got != tt.want {
				t.Errorf("PrefixUnderscroll() = %v, want %v", got, tt.want)
			}
		})
	}
}
