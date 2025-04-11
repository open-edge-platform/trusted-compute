/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func TestGenericPlatformFlavor_GetFlavorPartRaw(t *testing.T) {

	var tagCert *hvs.X509AttributeCertificate

	type fields struct {
		TagCertificate *hvs.X509AttributeCertificate
		Vendor         hcConstants.Vendor
	}
	type args struct {
		name hvs.FlavorPartName
	}

	// load tag cert
	if TagCertPath != "" {
		// load tagCert
		// read the test tag cert
		tagCertFile, err := os.Open(TagCertPath)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to open tagcert path %s", err)
		}
		tagCertPathBytes, err := ioutil.ReadAll(tagCertFile)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read tagcert file %s", err)
		}

		// convert pem to cert
		pemBlock, rest := pem.Decode(tagCertPathBytes)
		if len(rest) > 0 {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to decode tagcert %s", err)
		}
		tagCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to parse tagcert %s", err)
		}

		if tagCertificate != nil {
			tagCert, err = hvs.NewX509AttributeCertificate(tagCertificate)
			if err != nil {
				fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() Error while generating X509AttributeCertificate from TagCertificate")
			}
		}
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate GetFlavorPartRaw with valid data",
			fields: fields{
				TagCertificate: tagCert,
			},
			args: args{
				name: hvs.FlavorPartAssetTag,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gpf := GenericPlatformFlavor{
				TagCertificate: tt.fields.TagCertificate,
				Vendor:         tt.fields.Vendor,
			}
			_, err := gpf.GetFlavorPartRaw(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericPlatformFlavor.GetFlavorPartRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
