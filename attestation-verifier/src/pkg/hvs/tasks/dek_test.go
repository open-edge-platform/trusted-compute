/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/base64"
	"testing"
)

func TestCreateDek_SetName(t *testing.T) {
	type fields struct {
		DekStore *string
		Encode   *base64.Encoding
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Set command name",
			args: args{
				n: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cd := &CreateDek{
				DekStore: tt.fields.DekStore,
				Encode:   tt.fields.Encode,
			}
			cd.SetName(tt.args.n, tt.args.e)
		})
	}
}
