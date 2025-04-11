/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"os"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	err := os.Setenv("BEARER_TOKEN", "TEST123")
	if err != nil {
		log.Println("Failed to set ENV BEARER_TOKEN")
	}
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Valid Case",
			want: "TEST123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetBearerToken(); got != tt.want {
				t.Errorf("GetBearerToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
