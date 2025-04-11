/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
)

func TestPlatformFlavorUtil_GetMetaSectionDetails(t *testing.T) {
	type args struct {
		hostDetails    *taModel.HostInfo
		tagCertificate *hvs.X509AttributeCertificate
		xmlMeasurement string
		flavorPartName hvs.FlavorPartName
		vendor         hcConstants.Vendor
	}
	tpm := taModel.TPM{}
	meta := tpm.Meta

	var validHostInfo taModel.HostInfo
	err := json.Unmarshal([]byte(hostInfoJson), &validHostInfo)
	assert.NoError(t, err)

	measurement := taModel.Measurement{
		CumulativeHash: "b17bf9c2ba8d25cd87008d749591f72f5ae82ef0906e4855ca9e687d85fc299c",
		DigestAlg:      "SHA384",
		Label:          "Sha-384",
	}

	xmlMeasurement, err := xml.Marshal(&measurement)
	assert.NoError(t, err)

	tests := []struct {
		name    string
		pfutil  PlatformFlavorUtil
		args    args
		wantErr bool
	}{
		{
			name:    "Validate GetMetaSectionDetails with invalid Host Details",
			wantErr: true,
		},
		{
			name: "Validate GetMetaSectionDetails with invalid Flavor part",
			args: args{
				hostDetails: &taModel.HostInfo{
					HardwareFeatures: taModel.HardwareFeatures{
						TPM: &taModel.TPM{
							Meta: meta,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Validate GetMetaSectionDetails with valid - platform flavor",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartPlatform,
			},
			wantErr: false,
		},
		{
			name: "Validate GetMetaSectionDetails with valid - os flavor",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartOs,
			},
			wantErr: false,
		},
		{
			name: "Validate GetMetaSectionDetails with valid - host unique flavor",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartHostUnique,
			},
			wantErr: false,
		},
		{
			name: "Validate GetMetaSectionDetails with invalid - host unique flavor",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartSoftware,
			},
			wantErr: true,
		},
		{
			name: "Validate GetMetaSectionDetails with valid - software flavor",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartSoftware,
				xmlMeasurement: string(xmlMeasurement),
			},
			wantErr: false,
		},
		{
			name: "Validate GetMetaSectionDetails with valid asset tag flavor - Host details",
			args: args{
				hostDetails:    &validHostInfo,
				flavorPartName: hvs.FlavorPartAssetTag,
				tagCertificate: &hvs.X509AttributeCertificate{
					Subject: "!@#$%^&*()",
				},
			},
			wantErr: false,
		},
		{
			name: "Validate GetMetaSectionDetails with asset tag flavor - Tag certificate -Invalid hardware uuid",
			args: args{
				flavorPartName: hvs.FlavorPartAssetTag,
				tagCertificate: &hvs.X509AttributeCertificate{
					Subject: "!@#$%^&*()",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate GetMetaSectionDetails with valid asset tag flavor - tag certificate",
			args: args{
				flavorPartName: hvs.FlavorPartAssetTag,
				tagCertificate: &hvs.X509AttributeCertificate{
					Subject: "e213ea2e-d5cb-4024-bfc6-66890f6d0aa8",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			_, err := pfutil.GetMetaSectionDetails(tt.args.hostDetails, tt.args.tagCertificate, tt.args.xmlMeasurement, tt.args.flavorPartName, tt.args.vendor)
			if (err != nil) != tt.wantErr {
				t.Errorf("PlatformFlavorUtil.GetMetaSectionDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var hostInfoJson = `{
	"os_name":"RedhatEnterprise",
	"os_version":"8.2",
	"os_type":"Linux",
	"bios_version":"1.21.1",
	"vmm_name":"Test",
	"vmm_version":"2.0",
	"processor_info":"Test",
	"host_name":"Test",
	"bios_name":"Test",
	"hardware_uuid":"e213ea2e-d5cb-4024-bfc6-66890f6d0aa8",
	"process_flags":"Test",
	"no_of_sockets":"0",
	"tboot_installed":"true",
	"is_docker_env":"true",
	"hardware_features":{
	   "TXT":{
		  "enabled":"true"
	   },
	   "TPM":{
		  "enabled":"true",
		  "meta":{
			 "tpm_version":"2.0"
		  }
	   },
	   "CBNT":{
		  "enabled":"true",
		  "meta":{
			 "profile":"test",
			 "msr":"test"
		  }
	   },
	   "UEFI":{
		  "enabled":"true",
		  "meta":{
			 "secure_boot_enabled":true
		  }
	   },
	   "PFR":{
		  "enabled":"true"
	   },
	   "BMC":{
		  "enabled":"true"
	   }
	},
	"installed_components":null
 }
 `

func TestPlatformFlavorUtil_GetBiosSectionDetails(t *testing.T) {
	type args struct {
		hostDetails *taModel.HostInfo
	}
	tests := []struct {
		name   string
		pfutil PlatformFlavorUtil
		args   args
		want   *hvs.Bios
	}{
		{
			name: "Validate GetBiosSectionDetails With Host details",
			args: args{
				hostDetails: &taModel.HostInfo{
					BiosName:    "Test",
					BiosVersion: "2.0",
				},
			},
			want: &hvs.Bios{
				BiosName:    "Test",
				BiosVersion: "2.0",
			},
		},
		{
			name: "Validate GetBiosSectionDetails without Host details",
			args: args{
				hostDetails: nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			if got := pfutil.GetBiosSectionDetails(tt.args.hostDetails); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PlatformFlavorUtil.GetBiosSectionDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlatformFlavorUtil_GetHardwareSectionDetails(t *testing.T) {
	type args struct {
		hostManifest *hvs.HostManifest
	}

	var validHostInfo taModel.HostInfo
	err := json.Unmarshal([]byte(hostInfoJson), &validHostInfo)
	assert.NoError(t, err)

	var feature *hvs.Feature
	err = json.Unmarshal([]byte(featureJson), &feature)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		pfutil PlatformFlavorUtil
		args   args
		want   *hvs.Hardware
	}{
		{
			name: "Validate GetHardwareSectionDetails with valid data",
			args: args{
				hostManifest: &hvs.HostManifest{
					HostInfo: validHostInfo,
					PcrManifest: hvs.PcrManifest{
						Sha1Pcrs:   []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "a9993e364706816aba3e25717850c26c9cd0d89d"}},
						Sha256Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
						Sha384Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}},
					},
				},
			},
			want: &hvs.Hardware{
				ProcessorInfo:  "Test",
				ProcessorFlags: "Test",
				Feature:        feature,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			if got := pfutil.GetHardwareSectionDetails(tt.args.hostManifest); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PlatformFlavorUtil.GetHardwareSectionDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}

var featureJson = `{
	"TXT": {
	  "enabled": "true"
	},
	"TPM": {
	  "enabled": "true",
	  "meta": {
		"tpm_version": "2.0",
		"pcr_banks": ["SHA1","SHA256","SHA384"]
	  }
	},
	"CBNT": {
	  "enabled": "true",
	  "meta": {
		"profile": "test",
		"msr": "test"
	  }
	},
	"UEFI": {
	  "enabled": "true",
	  "meta": {
		"secure_boot_enabled": true
	  }
	},
	"PFR": {
	  "enabled": "true"
	},
	"BMC": {
	  "enabled": "true"
	}
  }`

func TestPlatformFlavorUtil_GetPcrDetails(t *testing.T) {
	type args struct {
		pcrManifest hvs.PcrManifest
		pcrList     map[hvs.PcrIndex]hvs.PcrListRules
	}

	pcrListEquals := make(map[hvs.PcrIndex]hvs.PcrListRules)
	pcrListEquals[0] = hvs.PcrListRules{
		PcrBank:    []string{"SHA1", "SHA256", "SHA384"},
		PcrMatches: true,
		PcrEquals: hvs.PcrEquals{
			IsPcrEquals:   true,
			ExcludingTags: map[string]bool{"Test": true},
		},
	}

	pcrListIncludes := make(map[hvs.PcrIndex]hvs.PcrListRules)
	pcrListIncludes[0] = hvs.PcrListRules{
		PcrBank:     []string{"SHA1", "SHA256", "SHA384"},
		PcrMatches:  true,
		PcrIncludes: map[string]bool{"Test": true},
	}
	tests := []struct {
		name   string
		pfutil PlatformFlavorUtil
		args   args
	}{
		{
			name: "GetPcrDetails with valid tags - Equals Rule",
			args: args{
				pcrManifest: hvs.PcrManifest{
					Sha1Pcrs:   []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "a9993e364706816aba3e25717850c26c9cd0d89d"}},
					Sha256Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
					Sha384Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}},
					PcrEventLogMap: hvs.PcrEventLogMap{
						Sha1EventLogs:   []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA1"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "a9993e364706816aba3e25717850c26c9cd0d89d"}}}},
						Sha256EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA256"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}},
						Sha384EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA384"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}}}},
					},
				},
				pcrList: pcrListEquals,
			},
		},
		{
			name: " GetPcrDetails with valid tags - Includes Rule",
			args: args{
				pcrManifest: hvs.PcrManifest{
					Sha1Pcrs:   []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "a9993e364706816aba3e25717850c26c9cd0d89d"}},
					Sha256Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
					Sha384Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}},
					PcrEventLogMap: hvs.PcrEventLogMap{
						Sha1EventLogs:   []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA1"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "a9993e364706816aba3e25717850c26c9cd0d89d"}}}},
						Sha256EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA256"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}},
						Sha384EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA384"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Tags: []string{"Test"}, Measurement: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}}}},
					},
				},
				pcrList: pcrListIncludes,
			},
		},
		{
			name: "GetPcrDetails with valid tags - Equals rule",
			args: args{
				pcrManifest: hvs.PcrManifest{
					Sha1Pcrs:   []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "a9993e364706816aba3e25717850c26c9cd0d89d"}},
					Sha256Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
					Sha384Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}},
					PcrEventLogMap: hvs.PcrEventLogMap{
						Sha1EventLogs:   []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA1"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "a9993e364706816aba3e25717850c26c9cd0d89d"}}}},
						Sha256EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA256"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}},
						Sha384EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA384"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}}}},
					},
				},
				pcrList: pcrListEquals,
			},
		},
		{
			name: "GetPcrDetails with valid tags - Includes rule",
			args: args{
				pcrManifest: hvs.PcrManifest{
					Sha1Pcrs:   []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "a9993e364706816aba3e25717850c26c9cd0d89d"}},
					Sha256Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
					Sha384Pcrs: []hvs.HostManifestPcrs{hvs.HostManifestPcrs{Index: 0, Value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}},
					PcrEventLogMap: hvs.PcrEventLogMap{
						Sha1EventLogs:   []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA1"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "a9993e364706816aba3e25717850c26c9cd0d89d"}}}},
						Sha256EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA256"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}},
						Sha384EventLogs: []hvs.TpmEventLog{hvs.TpmEventLog{Pcr: hvs.Pcr{Index: 0, Bank: "SHA384"}, TpmEvent: []hvs.EventLog{hvs.EventLog{TypeID: "1", TypeName: "Test", Measurement: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"}}}},
					},
				},
				pcrList: pcrListIncludes,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			pfutil.GetPcrDetails(tt.args.pcrManifest, tt.args.pcrList)
		})
	}
}

func TestPlatformFlavorUtil_GetExternalConfigurationDetails(t *testing.T) {
	type args struct {
		tagCertificate *hvs.X509AttributeCertificate
	}
	tests := []struct {
		name    string
		pfutil  PlatformFlavorUtil
		args    args
		want    *hvs.External
		wantErr bool
	}{
		{
			name: "GetExternalConfigurationDetails with valid tag certificate",
			args: args{
				tagCertificate: &hvs.X509AttributeCertificate{},
			},
			want: &hvs.External{
				AssetTag: hvs.AssetTag{
					TagCertificate: hvs.X509AttributeCertificate{},
				},
			},
			wantErr: false,
		},
		{
			name: "GetExternalConfigurationDetails with invalid tag certificate",
			args: args{
				tagCertificate: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			got, err := pfutil.GetExternalConfigurationDetails(tt.args.tagCertificate)
			if (err != nil) != tt.wantErr {
				t.Errorf("PlatformFlavorUtil.GetExternalConfigurationDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PlatformFlavorUtil.GetExternalConfigurationDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlatformFlavorUtil_GetSignedFlavorList(t *testing.T) {
	type args struct {
		flavors                 []hvs.Flavor
		flavorSigningPrivateKey *rsa.PrivateKey
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}

	tests := []struct {
		name    string
		pfutil  PlatformFlavorUtil
		args    args
		wantErr bool
	}{
		{
			name: "Validate GetSignedFlavorList with valid flavor",
			args: args{
				flavors: []hvs.Flavor{
					hvs.Flavor{},
				},
				flavorSigningPrivateKey: privatekey,
			},
			wantErr: false,
		},
		{
			name: "Validate GetSignedFlavorList with Missing flavors",
			args: args{
				flavors:                 nil,
				flavorSigningPrivateKey: privatekey,
			},
			wantErr: true,
		},
		{
			name: "Validate GetSignedFlavorList with Missing signing key",
			args: args{
				flavors: []hvs.Flavor{
					hvs.Flavor{},
				},
				flavorSigningPrivateKey: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			_, err := pfutil.GetSignedFlavorList(tt.args.flavors, tt.args.flavorSigningPrivateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PlatformFlavorUtil.GetSignedFlavorList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPlatformFlavorUtil_GetPcrRulesMap(t *testing.T) {
	type args struct {
		flavorPart      hvs.FlavorPartName
		flavorTemplates []hvs.FlavorTemplate
	}
	var fTemplate hvs.FlavorTemplate
	var fTemplates []hvs.FlavorTemplate
	template, err := ioutil.ReadFile("../../../../build/linux/hvs/templates/default-linux-rhel-tpm20-tboot.json")
	if err != nil {
		log.Error("Error in reading file", err)
	}
	json.Unmarshal(template, &fTemplate)
	fTemplates = append(fTemplates, fTemplate)

	tests := []struct {
		name    string
		pfutil  PlatformFlavorUtil
		args    args
		wantErr bool
	}{
		{
			name: "Platform flavor",
			args: args{
				flavorPart:      hvs.FlavorPartPlatform,
				flavorTemplates: fTemplates,
			},
			wantErr: false,
		},
		{
			name: "OS flavor",
			args: args{
				flavorPart:      hvs.FlavorPartOs,
				flavorTemplates: fTemplates,
			},
			wantErr: false,
		},
		{
			name: "Host Unique flavor",
			args: args{
				flavorPart:      hvs.FlavorPartHostUnique,
				flavorTemplates: fTemplates,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pfutil := PlatformFlavorUtil{}
			_, err := pfutil.GetPcrRulesMap(tt.args.flavorPart, tt.args.flavorTemplates)
			if (err != nil) != tt.wantErr {
				t.Errorf("PlatformFlavorUtil.GetPcrRulesMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
