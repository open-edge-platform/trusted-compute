/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"fmt"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
)

func TestGetVersion(t *testing.T) {
	Version = "1"
	GitHash = "abc123"
	BuildDate = "01-01-2001"

	wantStr := fmt.Sprintf("Service Name: %s\n", constants.ExplicitServiceName)
	wantStr = wantStr + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	wantStr = wantStr + fmt.Sprintf("Build Date: %s\n", BuildDate)

	tests := []struct {
		name string
		want string
	}{
		{
			name: "Validate GetVersion",
			want: wantStr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
