/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"testing"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func Test_hostTrustCache_addTrustedFlavors(t *testing.T) {
	type fields struct {
		hostID         uuid.UUID
		trustedFlavors map[uuid.UUID]*hvs.Flavor
		trustReport    hvs.TrustReport
	}
	type args struct {
		f *hvs.Flavor
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Add trusted flavors",
			fields: fields{
				hostID:         uuid.Nil,
				trustedFlavors: nil,
				trustReport:    hvs.TrustReport{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			htc := &hostTrustCache{
				hostID:         tt.fields.hostID,
				trustedFlavors: tt.fields.trustedFlavors,
				trustReport:    tt.fields.trustReport,
			}
			htc.addTrustedFlavors(tt.args.f)
		})
	}
}

func Test_hostTrustCache_removeTrustedFlavors(t *testing.T) {
	type fields struct {
		hostID         uuid.UUID
		trustedFlavors map[uuid.UUID]*hvs.Flavor
		trustReport    hvs.TrustReport
	}
	type args struct {
		fIn *hvs.Flavor
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test case 1",
			fields: fields{
				hostID:         uuid.Nil,
				trustedFlavors: nil,
				trustReport:    hvs.TrustReport{},
			},
			args: args{
				fIn: &hvs.Flavor{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			htc := &hostTrustCache{
				hostID:         tt.fields.hostID,
				trustedFlavors: tt.fields.trustedFlavors,
				trustReport:    tt.fields.trustReport,
			}
			htc.removeTrustedFlavors(tt.args.fIn)
		})
	}
}
