/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"os"
	"testing"
)

var sampleJson = `{
    "hardware_uuid": "80acb25c-95bd-e811-906e-00163566263e",
    "selection_content": [
        {
            "name": "state",
            "value": "Karnataka"
        },
        {
            "name": "city",
            "value": "chennai"
        },
        {
            "name": "Company",
            "value": "AMI"
        }
    ]
}`

func TestSaveToJsonFile(t *testing.T) {
	type args struct {
		path string
		obj  interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate SaveToJsonFile",
			args: args{
				path: "SampleJson",
				obj:  sampleJson,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveToJsonFile(tt.args.path, tt.args.obj); (err != nil) != tt.wantErr {
				t.Errorf("SaveToJsonFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("SampleJson")
}

func TestLoadFromJsonFile(t *testing.T) {
	type args struct {
		path string
		out  interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate LoadFromJsonFile for Read file error",
			args: args{
				path: "SampleJson",
			},
			wantErr: true,
		},
		{
			name: "Validate LoadFromJsonFile for Unmarshalling error",
			args: args{
				path: "test.yml",
				out:  TestObj{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadFromJsonFile(tt.args.path, tt.args.out); (err != nil) != tt.wantErr {
				t.Errorf("LoadFromJsonFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
