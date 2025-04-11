/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

const (
	ManifestPath       string = "../test/resources/HostManifest1.json"
	ManifestPathVmWare string = "../test/resources/HostManifest_VmWare.json"
	TagCertPath        string = "../test/resources/AssetTagpem.Cert"
	FlavorTemplatePath string = "../test/resources/TestTemplate.json"
)

var flavorTemplates []hvs.FlavorTemplate

func getFlavorTemplates(osName string, templatePath string) []hvs.FlavorTemplate {

	var template hvs.FlavorTemplate
	var templates []hvs.FlavorTemplate

	if strings.EqualFold(osName, "VMWARE ESXI") {
		return nil
	}

	// load hostmanifest
	if templatePath != "" {
		templateFile, err := os.Open(templatePath)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to open template path %s", err)
		}

		templateFileBytes, err := ioutil.ReadAll(templateFile)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read template file %s", err)
		}
		err = json.Unmarshal(templateFileBytes, &template)
		if err != nil {
			fmt.Printf("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall flavor template %s", err)
		}
		templates = append(templates, template)
	}
	return templates
}

func TestLinuxPlatformFlavor_GetPcrDetails(t *testing.T) {

	var hm *hvs.HostManifest
	var tagCert *hvs.X509AttributeCertificate

	hmBytes, err := ioutil.ReadFile(ManifestPath)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read hostmanifest file : ", err)
	}

	err = json.Unmarshal(hmBytes, &hm)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall hostmanifest : ", err)
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

	tagCertBytes, err := ioutil.ReadFile(TagCertPath)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read tagcertificate file : ", err)
	}

	err = json.Unmarshal(tagCertBytes, &tagCert)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall tagcertificate : ", err)
	}

	testPcrList := make(map[hvs.PcrIndex]hvs.PcrListRules)
	testPcrList[17] = hvs.PcrListRules{
		PcrBank:    []string{"SHA384", "SHA256", "SHA1"},
		PcrMatches: true,
		PcrEquals: hvs.PcrEquals{
			IsPcrEquals:   false,
			ExcludingTags: map[string]bool{"LCP_CONTROL_HASH": true, "initrd": true},
		},
	}

	testPcrList[18] = hvs.PcrListRules{
		PcrBank:    []string{"SHA384", "SHA256", "SHA1"},
		PcrMatches: true,
		PcrEquals: hvs.PcrEquals{
			IsPcrEquals: false,
		},
		PcrIncludes: map[string]bool{"LCP_CONTROL_HASH": true},
	}

	type fields struct {
		HostManifest    *hvs.HostManifest
		HostInfo        *taModel.HostInfo
		TagCertificate  *hvs.X509AttributeCertificate
		FlavorTemplates []hvs.FlavorTemplate
	}
	type args struct {
		pcrManifest     hvs.PcrManifest
		pcrList         map[hvs.PcrIndex]hvs.PcrListRules
		includeEventLog bool
	}

	testFields := fields{
		HostManifest:    hm,
		HostInfo:        &hm.HostInfo,
		TagCertificate:  tagCert,
		FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []hvs.FlavorPcrs
		wantErr bool
	}{
		{
			name:   "Validate GetPcrDetails while including event log",
			fields: testFields,
			args: args{
				pcrManifest:     hm.PcrManifest,
				pcrList:         testPcrList,
				includeEventLog: true,
			},
		},
		{
			name:   "Validate GetPcrDetails without including event log",
			fields: testFields,
			args: args{
				pcrManifest:     hm.PcrManifest,
				pcrList:         testPcrList,
				includeEventLog: false,
			},
		},
	}
	for _, tt := range tests {
		var got []hvs.FlavorPcrs
		t.Run(tt.name, func(t *testing.T) {
			rhelpf := HostPlatformFlavor{
				HostManifest:    tt.fields.HostManifest,
				HostInfo:        tt.fields.HostInfo,
				TagCertificate:  tt.fields.TagCertificate,
				FlavorTemplates: tt.fields.FlavorTemplates,
			}
			if got = pfutil.GetPcrDetails(rhelpf.HostManifest.PcrManifest, tt.args.pcrList); len(got) == 0 {
				t.Errorf("LinuxPlatformFlavor.GetPcrDetails() unable to perform GetPcrDetails")
			}
		})
	}
}

func TestHostPlatformFlavor_GetFlavorPartRaw(t *testing.T) {
	type fields struct {
		HostManifest    *hvs.HostManifest
		HostInfo        *taModel.HostInfo
		TagCertificate  *hvs.X509AttributeCertificate
		FlavorTemplates []hvs.FlavorTemplate
	}
	type args struct {
		name hvs.FlavorPartName
	}

	var hm *hvs.HostManifest
	var hmVmWare *hvs.HostManifest
	var tagCert *hvs.X509AttributeCertificate

	hmBytes, err := ioutil.ReadFile(ManifestPath)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read hostmanifest file : ", err)
	}

	err = json.Unmarshal(hmBytes, &hm)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall hostmanifest : ", err)
	}

	hmBytes, err = ioutil.ReadFile(ManifestPathVmWare)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read hostmanifest file : ", err)
	}

	err = json.Unmarshal(hmBytes, &hmVmWare)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall hostmanifest : ", err)
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
		want    []hvs.Flavor
		wantErr bool
	}{
		{
			name: "Validate GetFlavorPartRaw with valid Platform Flavor",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartPlatform,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with valid OS Flavor",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartOs,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with valid HostUnique Flavor",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartHostUnique,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with valid Asset tag Flavor - Linux",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartAssetTag,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with valid Asset tag Flavor - VmWare",
			fields: fields{
				HostManifest:    hmVmWare,
				HostInfo:        &hmVmWare.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartAssetTag,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with valid Software Flavor",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: hvs.FlavorPartSoftware,
			},
			wantErr: false,
		},
		{
			name: "Validate GetFlavorPartRaw with Unknown Flavor Part",
			fields: fields{
				HostManifest:    hm,
				HostInfo:        &hm.HostInfo,
				TagCertificate:  tagCert,
				FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
			},
			args: args{
				name: "Test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := HostPlatformFlavor{
				HostManifest:    tt.fields.HostManifest,
				HostInfo:        tt.fields.HostInfo,
				TagCertificate:  tt.fields.TagCertificate,
				FlavorTemplates: tt.fields.FlavorTemplates,
			}
			_, err := pf.GetFlavorPartRaw(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("HostPlatformFlavor.GetFlavorPartRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestHostPlatformFlavor_GetFlavorPartNames(t *testing.T) {
	type fields struct {
		HostManifest    *hvs.HostManifest
		HostInfo        *taModel.HostInfo
		TagCertificate  *hvs.X509AttributeCertificate
		FlavorTemplates []hvs.FlavorTemplate
	}

	var hm *hvs.HostManifest

	hmBytes, err := ioutil.ReadFile(ManifestPath)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read hostmanifest file : ", err)
	}

	err = json.Unmarshal(hmBytes, &hm)
	if err != nil {
		fmt.Println("flavor/util/host_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall hostmanifest : ", err)
	}

	tests := []struct {
		name    string
		fields  fields
		want    []hvs.FlavorPartName
		wantErr bool
	}{
		{
			name: "Validate Linux platform",
			fields: fields{
				HostManifest: hm,
			},
			want: []hvs.FlavorPartName{
				hvs.FlavorPartPlatform, hvs.FlavorPartOs,
				hvs.FlavorPartHostUnique, hvs.FlavorPartSoftware,
				hvs.FlavorPartAssetTag},
			wantErr: false,
		},
		{
			name: "Validate Other platforms",
			fields: fields{
				HostManifest: &hvs.HostManifest{
					HostInfo: taModel.HostInfo{
						OSName: "Test",
					},
				},
			},
			want: []hvs.FlavorPartName{
				hvs.FlavorPartPlatform, hvs.FlavorPartOs,
				hvs.FlavorPartHostUnique,
				hvs.FlavorPartAssetTag},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := HostPlatformFlavor{
				HostManifest:    tt.fields.HostManifest,
				HostInfo:        tt.fields.HostInfo,
				TagCertificate:  tt.fields.TagCertificate,
				FlavorTemplates: tt.fields.FlavorTemplates,
			}
			_, err := pf.GetFlavorPartNames()
			if (err != nil) != tt.wantErr {
				t.Errorf("HostPlatformFlavor.GetFlavorPartNames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewHostPlatformFlavor(t *testing.T) {
	type args struct {
		hostReport      *hvs.HostManifest
		tagCertificate  *hvs.X509AttributeCertificate
		flavorTemplates []hvs.FlavorTemplate
	}
	tests := []struct {
		name string
		args args
		want PlatformFlavor
	}{
		{
			name: "Valid case 1",
			args: args{
				hostReport: &hvs.HostManifest{
					HostInfo: model.HostInfo{},
				},
				tagCertificate:  &hvs.X509AttributeCertificate{},
				flavorTemplates: nil,
			},
			want: HostPlatformFlavor{
				HostManifest:    &hvs.HostManifest{},
				HostInfo:        &model.HostInfo{},
				TagCertificate:  &hvs.X509AttributeCertificate{},
				FlavorTemplates: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewHostPlatformFlavor(tt.args.hostReport, tt.args.tagCertificate, tt.args.flavorTemplates); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHostPlatformFlavor() = %v, want %v", got, tt.want)
			}
		})
	}
}
