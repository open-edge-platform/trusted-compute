/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"reflect"
	"testing"
)

func TestNewHostInfoParser(t *testing.T) {
	tests := []struct {
		name string
		want HostInfoParser
	}{
		{
			name: "Validate host info parser with valid data",
			want: &hostInfoParserImpl{
				parsers: []InfoParser{
					&smbiosInfoParser{},
					&osInfoParser{},
					&msrInfoParser{},
					&tpmInfoParser{},
					&shellInfoParser{},
					&fileInfoParser{},
					&miscInfoParser{},
					&secureBootParser{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewHostInfoParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHostInfoParser() = %v, want %v", got, tt.want)
			}
		})
	}
}
