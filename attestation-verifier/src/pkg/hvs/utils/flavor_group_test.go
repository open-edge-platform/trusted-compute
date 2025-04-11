/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func TestCreateFlavorGroupByName(t *testing.T) {
	type args struct {
		flavorgroupName string
	}
	tests := []struct {
		name string
		args args
		want hvs.FlavorGroup
	}{
		{
			name: "Valid case - creates flavor group using name provided",
			args: args{
				flavorgroupName: "automatic",
			},
			want: hvs.FlavorGroup{
				Name:          "automatic",
				MatchPolicies: GetAutomaticFlavorMatchPolicy(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateFlavorGroupByName(tt.args.flavorgroupName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateFlavorGroupByName() = %v, want %v", got, tt.want)
			}
		})
	}
}
