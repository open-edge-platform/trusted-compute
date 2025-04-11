/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import "testing"

func TestEncryptAndDecryptString(t *testing.T) {
	type args struct {
		plainText string
		key       []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Valid case - encrypts and decrypts text",
			args: args{
				plainText: "Sample text",
				key:       []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
			},
			want:    "Sample text",
			wantErr: false,
		},
		{
			name: "Invalid key",
			args: args{
				plainText: "Sample text",
				key:       []byte("test"),
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptString(tt.args.plainText, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err = DecryptString(got, tt.args.key)
			if got != tt.want {
				t.Errorf("EncryptString() = %v, want %v", got, tt.want)
			}
		})
	}
}
