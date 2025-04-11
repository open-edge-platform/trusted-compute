/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	flavorVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func TestVerifier_validateCachedFlavors(t *testing.T) {
	type fields struct {
		FlavorStore                     domain.FlavorStore
		FlavorGroupStore                domain.FlavorGroupStore
		HostStore                       domain.HostStore
		ReportStore                     domain.ReportStore
		FlavorVerifier                  flavorVerifier.Verifier
		CertsStore                      crypt.CertificatesStore
		SamlIssuer                      saml.IssuerConfiguration
		SkipFlavorSignatureVerification bool
		hostQuoteReportCache            map[uuid.UUID]*models.QuoteReportCache
		HostTrustCache                  *lru.Cache
	}
	var platform hvs.SignedFlavor
	json.Unmarshal([]byte(platformFlavor), &platform)
	var software hvs.SignedFlavor
	json.Unmarshal([]byte(softwareFlavor), &software)
	var hostStatus hvs.HostStatus
	json.Unmarshal([]byte(HostStatus1), hostStatus)
	type args struct {
		hostId        uuid.UUID
		hostData      *hvs.HostManifest
		cachedFlavors []hvs.SignedFlavor
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Trusted report - added in hostTrust cache",
			fields: fields{
				FlavorVerifier: &verify{errorStatus: "No error"},
				HostStore:      mocks.NewMockHostStore(),
			},
			args: args{hostId: hostStatus.ID,
				cachedFlavors: []hvs.SignedFlavor{platform, software},
				hostData:      &hostStatus.HostManifest,
			},
		},
		{
			name: "Trusted report - untrusted flavors",
			fields: fields{
				FlavorVerifier: &verify{errorStatus: "Contains faults"},
				HostStore:      mocks.NewMockHostStore(),
			},
			args: args{hostId: hostStatus.ID,
				cachedFlavors: []hvs.SignedFlavor{platform, software},
				hostData:      &hostStatus.HostManifest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				FlavorStore:                     tt.fields.FlavorStore,
				FlavorGroupStore:                tt.fields.FlavorGroupStore,
				HostStore:                       tt.fields.HostStore,
				ReportStore:                     tt.fields.ReportStore,
				FlavorVerifier:                  tt.fields.FlavorVerifier,
				CertsStore:                      tt.fields.CertsStore,
				SamlIssuer:                      tt.fields.SamlIssuer,
				SkipFlavorSignatureVerification: tt.fields.SkipFlavorSignatureVerification,
				hostQuoteReportCache:            tt.fields.hostQuoteReportCache,
				HostTrustCache:                  tt.fields.HostTrustCache,
			}
			_, err := v.validateCachedFlavors(tt.args.hostId, tt.args.hostData, tt.args.cachedFlavors)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.validateCachedFlavors() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
