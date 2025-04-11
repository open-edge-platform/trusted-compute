/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"os"
	"testing"
)

func TestSaveToYamlFile(t *testing.T) {
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
			name: "Validate save to yaml file",
			args: args{
				path: "SampleYaml",
				obj:  "Test",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveToYamlFile(tt.args.path, tt.args.obj); (err != nil) != tt.wantErr {
				t.Errorf("SaveToYamlFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("SampleYaml")
}

func TestLoadFromYamlFile(t *testing.T) {
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
			name: "Validate Load from yaml file with valid data",
			args: args{
				path: "test.yml",
				out:  &TestObj{},
			},
			wantErr: false,
		},
		{
			name: "Validate Load from yaml file with Read file error",
			args: args{
				path: "SampleYaml",
			},
			wantErr: true,
		},
		{
			name: "Validate Load from yaml file with Unmarshalling error",
			args: args{
				path: "json.go",
				out:  TestObj{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadFromYamlFile(tt.args.path, tt.args.out); (err != nil) != tt.wantErr {
				t.Errorf("LoadFromYamlFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
