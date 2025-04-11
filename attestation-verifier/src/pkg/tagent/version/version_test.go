/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"testing"
)

func Test_parseMajorVersion(t *testing.T) {
	tests := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{
			name:    "Negative Case 1 - Empty major version string",
			wantErr: true,
		},
		{
			name:    "Negative Case 2 - Could not parse major version string",
			wantErr: true,
		},
		{
			name:    "Positive Case",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Negative Case 2 - Could not parse major version string" {
				Version = "-$1.-1"
			} else if tt.name == "Positive Case" {
				Version = "1.0"
			}

			_, err := parseMajorVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMajorVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_parseMinorVersion(t *testing.T) {
	tests := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{
			name:    "Negative Case 1 - Empty minor version string",
			wantErr: true,
		},
		{
			name:    "Negative Case 2 - Could not parse minor version string",
			wantErr: true,
		},
		{
			name:    "Negative Case 3 - Invalid minor version string",
			wantErr: true,
		},
		{
			name:    "Positive Case 1 - valid minor version string",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Negative Case 2 - Could not parse minor version string" {
				Version = "1.0"
			} else if tt.name == "Negative Case 3 - Invalid minor version string" {
				Version = "1.-$2.-3"
			} else if tt.name == "Positive Case 1 - valid minor version string" {
				Version = "1.2.3"
			} else if tt.name == "Negative Case 1 - Empty minor version string" {
				Version = ""
			}

			_, err := parseMinorVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMinorVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_parsePatchVersion(t *testing.T) {
	tests := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{
			name:    "Negative Case 1 - Empty version string",
			wantErr: true,
		},
		{
			name:    "Negative Case 2 - Invalid version string",
			wantErr: true,
		},
		{
			name:    "Positive Case",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Negative Case 2 - Invalid version string" {
				Version = "1.2.$48"
			} else if tt.name == "Positive Case" {
				Version = "1.2.3"
			} else if tt.name == "Negative Case 1 - Empty version string" {
				Version = ""
			}

			_, err := parsePatchVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePatchVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Positive case",
			want: "Service Name: Trust Agent\nVersion: -\nBuild Date: \n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GetVersion()
		})
	}
}

func TestGetVersionInfo(t *testing.T) {
	tests := []struct {
		name    string
		want    *VersionInfo
		wantErr bool
	}{
		{
			name:    "Positive Case 1 - All as default",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Positive Case 2 - Provide BuildDate",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Positive Case 3 - Provide versionInfo",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Positive Case 4 - Provide Branch",
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Positive Case 2 - Provide BuildDate" {
				BuildDate = "Feb 4, 2014 at 6:05pm (PST)"
			} else if tt.name == "Positive Case 3 - Provide versionInfo" {
				versionInfo = &VersionInfo{Major: 1}
			} else if tt.name == "Positive Case 4 - Provide Branch" {
				Branch = "unit test"
			}

			_, err := GetVersionInfo()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVersionInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}
