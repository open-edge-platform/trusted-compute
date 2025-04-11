/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"testing"

	"github.com/google/uuid"
	flavorVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func Test_flvGrpHostTrustReqs_MeetsFlavorGroupReqs(t *testing.T) {
	type fields struct {
		HostId                          uuid.UUID
		FlavorGroupId                   uuid.UUID
		FlavorMatchPolicies             hvs.FlavorMatchPolicies
		MatchTypeFlavorParts            map[hvs.MatchType][]hvs.FlavorPartName
		AllOfFlavors                    []hvs.SignedFlavor
		DefinedAndRequiredFlavorTypes   map[hvs.FlavorPartName]bool
		FlavorPartMatchPolicy           map[hvs.FlavorPartName]hvs.MatchPolicy
		SkipFlavorSignatureVerification bool
	}
	type args struct {
		trustCache    hostTrustCache
		verifierCerts flavorVerifier.VerifierCertificates
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Trust cache is empty",
			fields: fields{
				HostId: uuid.MustParse("9ec95bdb-9700-4be7-939a-1c8bb342d8cb"),
			},
			args: args{
				trustCache: hostTrustCache{},
			},
			want: false,
		},
		{
			name: "Trust cache is not empty",
			fields: fields{
				HostId: uuid.MustParse("9ec95bdb-9700-4be7-939a-1c8bb342d8cb"),
			},
			args: args{
				trustCache: hostTrustCache{
					trustedFlavors: map[uuid.UUID]*hvs.Flavor{uuid.MustParse("9ec95bdb-9700-4be7-939a-1c8bb342d8cc"): &hvs.Flavor{}},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &flvGrpHostTrustReqs{
				HostId:                          tt.fields.HostId,
				FlavorGroupId:                   tt.fields.FlavorGroupId,
				FlavorMatchPolicies:             tt.fields.FlavorMatchPolicies,
				MatchTypeFlavorParts:            tt.fields.MatchTypeFlavorParts,
				AllOfFlavors:                    tt.fields.AllOfFlavors,
				DefinedAndRequiredFlavorTypes:   tt.fields.DefinedAndRequiredFlavorTypes,
				FlavorPartMatchPolicy:           tt.fields.FlavorPartMatchPolicy,
				SkipFlavorSignatureVerification: tt.fields.SkipFlavorSignatureVerification,
			}
			if got := r.MeetsFlavorGroupReqs(tt.args.trustCache, tt.args.verifierCerts); got != tt.want {
				t.Errorf("flvGrpHostTrustReqs.MeetsFlavorGroupReqs() = %v, want %v", got, tt.want)
			}
		})
	}
}
