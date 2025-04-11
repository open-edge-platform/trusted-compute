/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func Test_verifierImpl_GetVerifierCerts(t *testing.T) {
	type fields struct {
		verifierCertificates VerifierCertificates
	}
	tests := []struct {
		name   string
		fields fields
		want   VerifierCertificates
	}{
		{
			name: "Validate GetVerifierCerts with valid data",
			fields: fields{
				verifierCertificates: VerifierCertificates{},
			},
			want: VerifierCertificates{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verifierImpl{
				verifierCertificates: tt.fields.verifierCertificates,
			}
			if got := v.GetVerifierCerts(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifierImpl.GetVerifierCerts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_verifierImpl_Verify(t *testing.T) {
	type fields struct {
		verifierCertificates VerifierCertificates
	}
	type args struct {
		hostManifest                 *hvs.HostManifest
		signedFlavor                 *hvs.SignedFlavor
		skipSignedFlavorVerification bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *hvs.TrustReport
		wantErr bool
	}{
		{
			name: "Validate GetVerifierCerts with empty host manifest",
			fields: fields{
				verifierCertificates: VerifierCertificates{},
			},
			args: args{
				signedFlavor: &hvs.SignedFlavor{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Validate GetVerifierCerts with empty signed flavor",
			fields: fields{
				verifierCertificates: VerifierCertificates{},
			},
			args: args{
				hostManifest: &hvs.HostManifest{},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verifierImpl{
				verifierCertificates: tt.fields.verifierCertificates,
			}
			got, err := v.Verify(tt.args.hostManifest, tt.args.signedFlavor, tt.args.skipSignedFlavorVerification)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifierImpl.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifierImpl.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
