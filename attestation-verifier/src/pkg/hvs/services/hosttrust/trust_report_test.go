/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	flavorVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func Test_getMissingRequiredFlavorPartsWithLatest(t *testing.T) {
	type args struct {
		hostId               uuid.UUID
		reqs                 flvGrpHostTrustReqs
		reqAndDefFlavorTypes map[hvs.FlavorPartName]bool
		cachedTrustReport    hvs.TrustReport
	}
	tests := []struct {
		name string
		args args
		want map[hvs.FlavorPartName]bool
	}{
		{
			name: "List of missing required flavor part",
			args: args{
				hostId:               uuid.MustParse("85db555e-8662-4266-a28c-1809e26531f1"),
				reqAndDefFlavorTypes: map[hvs.FlavorPartName]bool{hvs.FlavorPartPlatform: true},
			},
			want: map[hvs.FlavorPartName]bool{hvs.FlavorPartPlatform: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getMissingRequiredFlavorPartsWithLatest(tt.args.hostId, tt.args.reqs, tt.args.reqAndDefFlavorTypes, tt.args.cachedTrustReport); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMissingRequiredFlavorPartsWithLatest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_verifyFlavors(t *testing.T) {
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
		hostID        uuid.UUID
		flavors       []hvs.SignedFlavor
		hostData      *hvs.HostManifest
		hostTrustReqs flvGrpHostTrustReqs
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *hvs.TrustReport
		wantErr bool
	}{
		{
			name: "Verification of flavors against hostmanifest",
			fields: fields{
				FlavorVerifier: &verify{errorStatus: "No error"},
			},
			args: args{hostID: hostStatus.ID,
				flavors:  []hvs.SignedFlavor{platform, software},
				hostData: &hostStatus.HostManifest,
				hostTrustReqs: flvGrpHostTrustReqs{
					FlavorMatchPolicies: hvs.FlavorMatchPolicies{hvs.FlavorMatchPolicy{FlavorPart: hvs.FlavorPartPlatform}},
				},
			},
			want: &hvs.TrustReport{
				HostManifest: *&hostStatus.HostManifest,
			},
			wantErr: false,
		},
		{
			name: "Verification of flavors against hostmanifest with faults",
			fields: fields{
				FlavorVerifier: &verify{errorStatus: "Contains faults"},
				HostStore:      mocks.NewMockHostStore(),
			},
			args: args{hostID: hostStatus.ID,
				flavors:  []hvs.SignedFlavor{platform, software},
				hostData: &hostStatus.HostManifest,
				hostTrustReqs: flvGrpHostTrustReqs{
					FlavorMatchPolicies: hvs.FlavorMatchPolicies{hvs.FlavorMatchPolicy{FlavorPart: hvs.FlavorPartPlatform,
						MatchPolicy: hvs.MatchPolicy{MatchType: hvs.MatchTypeAnyOf}}},
					FlavorPartMatchPolicy: map[hvs.FlavorPartName]hvs.MatchPolicy{hvs.FlavorPartPlatform: hvs.MatchPolicy{MatchType: hvs.MatchTypeAnyOf}},
				},
			},
			want: &hvs.TrustReport{
				HostManifest: *&hostStatus.HostManifest,
			},
			wantErr: false,
		},
		{
			name: "Verification of flavors against hostmanifest with software faults",
			fields: fields{
				FlavorVerifier: &verify{errorStatus: "Software flavor fault"},
				HostStore:      mocks.NewMockHostStore(),
			},
			args: args{hostID: hostStatus.ID,
				flavors:  []hvs.SignedFlavor{platform, software},
				hostData: &hostStatus.HostManifest,
				hostTrustReqs: flvGrpHostTrustReqs{
					FlavorMatchPolicies: hvs.FlavorMatchPolicies{hvs.FlavorMatchPolicy{FlavorPart: hvs.FlavorPartSoftware,
						MatchPolicy: hvs.MatchPolicy{MatchType: hvs.MatchTypeAllOf}}},
					FlavorPartMatchPolicy: map[hvs.FlavorPartName]hvs.MatchPolicy{hvs.FlavorPartSoftware: hvs.MatchPolicy{MatchType: hvs.MatchTypeAllOf}},
				},
			},
			want: &hvs.TrustReport{
				HostManifest: *&hostStatus.HostManifest,
			},
			wantErr: false,
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
			got, err := v.verifyFlavors(tt.args.hostID, tt.args.flavors, tt.args.hostData, tt.args.hostTrustReqs)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.verifyFlavors() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verifier.verifyFlavors() = %v, want %v", got, tt.want)
			}
		})
	}
}

type verify struct {
	errorStatus string
}

func (v *verify) Verify(hostManifest *hvs.HostManifest, signedFlavor *hvs.SignedFlavor, skipFlavorSignatureVerification bool) (*hvs.TrustReport, error) {
	if v.errorStatus == "No error" {
		return &hvs.TrustReport{
			Trusted: true,
		}, nil
	} else if v.errorStatus == "Contains faults" {
		trustReportBytes, _ := ioutil.ReadFile("../../domain/mocks/resources/fault_trust_report.json")
		var trustReport hvs.TrustReport
		err := json.Unmarshal(trustReportBytes, &trustReport)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error unmarshalling trust report")
		}
		return &trustReport, nil
	} else if v.errorStatus == "Software flavor fault" {
		trustReportBytes, _ := ioutil.ReadFile("../../domain/mocks/resources/software_fault_report.json")
		var trustReport hvs.TrustReport
		err := json.Unmarshal(trustReportBytes, &trustReport)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error unmarshalling trust report")
		}
		return &trustReport, nil
	}
	return nil, nil
}

func (*verify) GetVerifierCerts() verifier.VerifierCertificates {
	return verifier.VerifierCertificates{}
}

var platformFlavor = ` {
	"flavor": {
		"meta": {
			"id": "c36b5412-8c02-4e08-8a74-8bfa40425cf3",
			"description": {
				"flavor_part": "PLATFORM",
				"source": "Purley21",
				"label": "INTEL_IntelCorporation_SE5C620.86B.00.01.0014.070920180847_TXT_TPM_06-16-2020",
				"bios_name": "IntelCorporation",
				"bios_version": "SE5C620.86B.00.01.0014.070920180847",
				"tpm_version": "2.0",
				"tboot_installed": "true"
			},
			"vendor": "INTEL"
		},
		"bios": {
			"bios_name": "Intel Corporation",
			"bios_version": "SE5C620.86B.00.01.0014.070920180847"
		},
		"hardware": {
			"processor_info": "54 06 05 00 FF FB EB BF",
			"feature": {
				"tpm": {
					"enabled": true,
					"version": "2.0",
					"pcr_banks": [
						"SHA1",
						"SHA256"
					]
				},
				"txt": {
					"enabled": true
				}
			}
		},
		"pcrs": {
			"SHA1": {
				"pcr_0": {
					"value": "3f95ecbb0bb8e66e54d3f9e4dbae8fe57fed96f0"
				},
				"pcr_17": {
					"value": "460d626473202cb536b37d56dc0fd43438fae165",
					"event": [
						{
							"value": "19f7c22f6c92d9555d792466b2097443444ebd26",
							"label": "HASH_START",
							"info": {
								"ComponentName": "HASH_START",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "3cf4a5c90911c21f6ea71f4ca84425f8e65a2be7",
							"label": "BIOSAC_REG_DATA",
							"info": {
								"ComponentName": "BIOSAC_REG_DATA",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "3c585604e87f855973731fea83e21fab9392d2fc",
							"label": "CPU_SCRTM_STAT",
							"info": {
								"ComponentName": "CPU_SCRTM_STAT",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
							"label": "LCP_DETAILS_HASH",
							"info": {
								"ComponentName": "LCP_DETAILS_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
							"label": "STM_HASH",
							"info": {
								"ComponentName": "STM_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
							"label": "OSSINITDATA_CAP_HASH",
							"info": {
								"ComponentName": "OSSINITDATA_CAP_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e",
							"label": "MLE_HASH",
							"info": {
								"ComponentName": "MLE_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
							"label": "NV_INFO_HASH",
							"info": {
								"ComponentName": "NV_INFO_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
							"label": "tb_policy",
							"info": {
								"ComponentName": "tb_policy",
								"EventName": "OpenSource.EventName"
							}
						}
					]
				},
				"pcr_18": {
					"value": "86da61107994a14c0d154fd87ca509f82377aa30",
					"event": [
						{
							"value": "a395b723712b3711a89c2bb5295386c0db85fe44",
							"label": "SINIT_PUBKEY_HASH",
							"info": {
								"ComponentName": "SINIT_PUBKEY_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "3c585604e87f855973731fea83e21fab9392d2fc",
							"label": "CPU_SCRTM_STAT",
							"info": {
								"ComponentName": "CPU_SCRTM_STAT",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
							"label": "OSSINITDATA_CAP_HASH",
							"info": {
								"ComponentName": "OSSINITDATA_CAP_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
							"label": "LCP_AUTHORITIES_HASH",
							"info": {
								"ComponentName": "LCP_AUTHORITIES_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
							"label": "NV_INFO_HASH",
							"info": {
								"ComponentName": "NV_INFO_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
							"label": "tb_policy",
							"info": {
								"ComponentName": "tb_policy",
								"EventName": "OpenSource.EventName"
							}
						}
					]
				}
			},
			"SHA256": {
				"pcr_0": {
					"value": "1009d6bc1d92739e4e8e3c6819364f9149ee652804565b83bf731bdb6352b2a6"
				},
				"pcr_17": {
					"value": "c4a4b0b6601abc9756fdc0cecce173e781096e2ca0ce12650951a933821bd772",
					"event": [
						{
							"value": "14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db",
							"label": "HASH_START",
							"info": {
								"ComponentName": "HASH_START",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428",
							"label": "BIOSAC_REG_DATA",
							"info": {
								"ComponentName": "BIOSAC_REG_DATA",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
							"label": "CPU_SCRTM_STAT",
							"info": {
								"ComponentName": "CPU_SCRTM_STAT",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
							"label": "LCP_DETAILS_HASH",
							"info": {
								"ComponentName": "LCP_DETAILS_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
							"label": "STM_HASH",
							"info": {
								"ComponentName": "STM_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
							"label": "OSSINITDATA_CAP_HASH",
							"info": {
								"ComponentName": "OSSINITDATA_CAP_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186",
							"label": "MLE_HASH",
							"info": {
								"ComponentName": "MLE_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
							"label": "NV_INFO_HASH",
							"info": {
								"ComponentName": "NV_INFO_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
							"label": "tb_policy",
							"info": {
								"ComponentName": "tb_policy",
								"EventName": "OpenSource.EventName"
							}
						}
					]
				},
				"pcr_18": {
					"value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
					"event": [
						{
							"value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
							"label": "SINIT_PUBKEY_HASH",
							"info": {
								"ComponentName": "SINIT_PUBKEY_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
							"label": "CPU_SCRTM_STAT",
							"info": {
								"ComponentName": "CPU_SCRTM_STAT",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
							"label": "OSSINITDATA_CAP_HASH",
							"info": {
								"ComponentName": "OSSINITDATA_CAP_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
							"label": "LCP_AUTHORITIES_HASH",
							"info": {
								"ComponentName": "LCP_AUTHORITIES_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
							"label": "NV_INFO_HASH",
							"info": {
								"ComponentName": "NV_INFO_HASH",
								"EventName": "OpenSource.EventName"
							}
						},
						{
							"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
							"label": "tb_policy",
							"info": {
								"ComponentName": "tb_policy",
								"EventName": "OpenSource.EventName"
							}
						}
					]
				}
			}
		}
	},
	"signature": "EyuFK0QurCblcI8uRjzpn21gxvBdR99qtLDC1MEVuZ0bqLG4GC9qz27IjBO3Laniuu6e8RaVTkl6T2abnv3N+93VpSYHPKxM/ly7pM16fZmnIq1vQf0cC84tP4udL32mkq2l7riYxl8TupVrjMH9cc39Nd5JW8aRfLMcqqG6V3AHJD4mFdi0FAGDRMIlVq7WMjkZbZ8scVMH0ytJymRAq53Z8/ontdcWbXy3i1Lwrh9yrQufQ67g05UDjQJQTv+YXW9s0wR55O1I+RaZaxb3+lsBbtt7O21oT1+9CwIHN6gPP9L8OP3UDRPFN3mUA8rSHu3btnH1K1gEO1Dz+TnXIZ9puattdvOUTLjIIOMJcH/Y4ED0R3Bhln0PpRPxcgaD/Ku2dZxZWdhYHAkvIA5d8HquuAw6SkVoA5CH8DUkihSrbdQszbfpXWhFiTamfj7wpQLcacNsXES9IWvHD14GytBBfZ5lJhZ2I7OLF9QSivZh9P489upgH8rdV3qxY1jj"
}`

var softwareFlavor = `   {
	"flavor": {
		"meta": {
			"schema": {
				"uri": "lib:wml:measurements:1.0"
			},
			"id": "41eb98bc-aab9-4877-8b4a-e78f10148f06",
			"description": {
				"flavor_part": "SOFTWARE",
				"label": "ISecL_Default_Application_Flavor_v2.1_TPM2.0",
				"digest_algorithm": "SHA384"
			},
			"vendor": "INTEL"
		},
		"software": {
			"measurements": {
				"opt-tbootxm-bin": {
					"type": "directoryMeasurementType",
					"value": "b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a",
					"Path": "/opt/tbootxm/bin",
					"Include": ".*"
				},
				"opt-tbootxm-bin-configure_host.sh": {
					"type": "fileMeasurementType",
					"value": "8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c",
					"Path": "/opt/tbootxm/bin/configure_host.sh"
				},
				"opt-tbootxm-bin-functions.sh": {
					"type": "fileMeasurementType",
					"value": "8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0",
					"Path": "/opt/tbootxm/bin/functions.sh"
				},
				"opt-tbootxm-bin-generate_initrd.sh": {
					"type": "fileMeasurementType",
					"value": "4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4",
					"Path": "/opt/tbootxm/bin/generate_initrd.sh"
				},
				"opt-tbootxm-bin-measure": {
					"type": "fileMeasurementType",
					"value": "c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1",
					"Path": "/opt/tbootxm/bin/measure"
				},
				"opt-tbootxm-bin-measure_host": {
					"type": "fileMeasurementType",
					"value": "63648dde7ef979e0ce32fbb4fc2087bf861ca0c9a2755d13e2135eaecf37e9e43e7523ac923d8073b0fe6159da6aba4a",
					"Path": "/opt/tbootxm/bin/measure_host"
				},
				"opt-tbootxm-bin-tboot-xm-uninstall.sh": {
					"type": "fileMeasurementType",
					"value": "7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59",
					"Path": "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
				},
				"opt-tbootxm-bin-tpmextend": {
					"type": "fileMeasurementType",
					"value": "b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55",
					"Path": "/opt/tbootxm/bin/tpmextend"
				},
				"opt-tbootxm-dracut_files": {
					"type": "directoryMeasurementType",
					"value": "1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232",
					"Path": "/opt/tbootxm/dracut_files",
					"Include": ".*"
				},
				"opt-tbootxm-dracut_files-check": {
					"type": "fileMeasurementType",
					"value": "6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1",
					"Path": "/opt/tbootxm/dracut_files/check"
				},
				"opt-tbootxm-dracut_files-install": {
					"type": "fileMeasurementType",
					"value": "e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a",
					"Path": "/opt/tbootxm/dracut_files/install"
				},
				"opt-tbootxm-dracut_files-module-setup.sh": {
					"type": "fileMeasurementType",
					"value": "0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb",
					"Path": "/opt/tbootxm/dracut_files/module-setup.sh"
				},
				"opt-tbootxm-initrd_hooks": {
					"type": "directoryMeasurementType",
					"value": "77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7",
					"Path": "/opt/tbootxm/initrd_hooks",
					"Include": ".*"
				},
				"opt-tbootxm-initrd_hooks-tcb": {
					"type": "fileMeasurementType",
					"value": "430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98",
					"Path": "/opt/tbootxm/initrd_hooks/tcb"
				},
				"opt-tbootxm-lib": {
					"type": "directoryMeasurementType",
					"value": "b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb",
					"Path": "/opt/tbootxm/lib",
					"Include": ".*"
				},
				"opt-tbootxm-lib-create_menuentry.pl": {
					"type": "fileMeasurementType",
					"value": "79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
					"Path": "/opt/tbootxm/lib/create_menuentry.pl"
				},
				"opt-tbootxm-lib-libwml.so": {
					"type": "fileMeasurementType",
					"value": "56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378",
					"Path": "/opt/tbootxm/lib/libwml.so"
				},
				"opt-tbootxm-lib-remove_menuentry.pl": {
					"type": "fileMeasurementType",
					"value": "baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c",
					"Path": "/opt/tbootxm/lib/remove_menuentry.pl"
				},
				"opt-tbootxm-lib-update_menuentry.pl": {
					"type": "fileMeasurementType",
					"value": "cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e",
					"Path": "/opt/tbootxm/lib/update_menuentry.pl"
				},
				"opt-tbootxm-mkinitrd_files": {
					"type": "directoryMeasurementType",
					"value": "6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247",
					"Path": "/opt/tbootxm/mkinitrd_files",
					"Include": ".*"
				},
				"opt-tbootxm-mkinitrd_files-setup-measure_host.sh": {
					"type": "fileMeasurementType",
					"value": "2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc",
					"Path": "/opt/tbootxm/mkinitrd_files/setup-measure_host.sh"
				},
				"opt-trustagent-bin": {
					"type": "directoryMeasurementType",
					"value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
					"Path": "/opt/trustagent/bin",
					"Include": ".*"
				},
				"opt-trustagent-bin-module_analysis.sh": {
					"type": "fileMeasurementType",
					"value": "2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9",
					"Path": "/opt/trustagent/bin/module_analysis.sh"
				},
				"opt-trustagent-bin-module_analysis_da.sh": {
					"type": "fileMeasurementType",
					"value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
					"Path": "/opt/trustagent/bin/module_analysis_da.sh"
				},
				"opt-trustagent-bin-module_analysis_da_tcg.sh": {
					"type": "fileMeasurementType",
					"value": "0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242",
					"Path": "/opt/trustagent/bin/module_analysis_da_tcg.sh"
				},
				"opt-trustagent-bin-tagent": {
					"type": "fileMeasurementType",
					"value": "14de1f422595a231b4efc8c64a9fd5cfb7952182371b7856b4909864287f6eb62fed839f11b043948c39e238c61197cd",
					"Path": "/opt/trustagent/bin/tagent"
				}
			},
			"cumulative_hash": "1cb7f7d37adf57274620d44e687ffc9a184cd5ab5c5e434b30514241198b6ecbd029e2ab78072540b875f52d304bc042"
		}
	},
	"signature": "MkHPlueY+vqO9Dg8iaHORqqri3tw0xxs9SVLuySaDJdvKMITimABvzSd1mKmITUZWjwAmtMQgqCHn+K2LgZ4X0spELbNyCkPEKguK7QiO9rOdzwkdvUCMJAY7lrw9HuWpGoNZQocRyPtDjgrkKjEOO/sA7l/rormhqrat+ouPz7yHIIS3tNIQSlHSURn2lYYLDjqNjqnEyGrQRqoQT42RjXXBfkkgepmqxhEuV6WHdt5xD0r+TwSR3KZ4NZiGlgoXFTWj/RkVa/3Ru5QH0X/4RTAWzg0pHXY//S0Ag8ddEy2Z62B31N1TPp5Cl+fNQC5o5Cv3Q8yLNTAnUTI31pWNZyWeogJi38LRGH3b4XeFO7drPjsi5Oy6i/OqeehNPWzoaNHmW9NnTBEgprqfER9vE1/z3bjD/5BlHTfjGGlv8Ob+zgGTSzwwr/Lh0DOb+lURsa8qFEsjFgAAfgyQ5RAhIsnDHAQgS1/X5ObiMxZXimFuZvMO9mMf4clLZ/x/3Kq"
}`

var TimeDuration30Mins, _ = time.ParseDuration("30m")
var HostStatus1 = `{"id":"afed7372-18c3-42af-bd9a-70b7f44c11ad","host_id":"47a3b602-f321-4e03-b3b2-8f3ca3cde128","status":{"host_state":"CONNECTED"},"created":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","host_manifest":{ "aik_certificate": "MIIDTDCCAbSgAwIBAgIGAXF82oFMMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29uLXBjYS1haWswHhcNMjAwNDE1MDgwMDI2WhcNMzAwNDE1MDgwMDI2WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Ug7M15W3I3LejIOxZOiSvgXboF4+7TxvaY8BbzrNoyGbV8QfyCHjmdYHoyyzwvCUp9CB7wg1tb0btSLAqITLjFnUnTks28Sqz5tZW3et0O0X1fAsSnhJIc3vtkgxnxEIFOx2nsUDrEPXbdH1XOjSs5iRE7K45v2MzN9CO2QCwydPbUmgwauJNI3eQS5AZjF3eVnus9MMhTvYj4PNwbRj3jjuMH6OzJKX4bKeRPm05IHQcT/sEFoq5mShAmGyl+RkkRennIm5VIUnV99jm8mJvfZL3LA43kiHiOkvwiN0ImnDnNADP40IpothFFfIQEhr2L9CYUuUlq/BAkgt9epdwIDAQABozEwLzAtBgNVHREBAf8EIzAhgR8ACxj9Cf0C/f0bOXZ4QSn9JP1LQf13QWAZEV5Bsnz9MA0GCSqGSIb3DQEBCwUAA4IBgQA/SUjxvk2e6zgmTm5VhoV4WMmvvfZWZqEuKNnNB4lIkfySLuETTU7Jw1lc4skgr3KvxoftRM0099WVxhVwQMK/MarE7yNW7JQr2byNLoOrVm6FSkcRowrGFEnvFtC/qiGQ9JQTRkormIxDuPsaZWVjHMEuefEyq9T+hueTP5a1NDJmvtlXD2MjMjwEzeGf7R3TURmXt6tjMotbyO0/uv1n3Q79Wl/yWzb+bs9g5QlIlSrDGaxK7c7I7jGh0ee2gS2BOa/9iS59B9AS1TwACyj47yjFXoSQsvWqZ7XfPPzFVcFvvwtLRLeOzgIZhD+ZXutmY+smqDnkh/PB5BmXM/zDlae4QJ71rBGrmvVVj2cWGdaeZ19JivLLiBw0164yehTcpDzQzZQqyY4X+kX+fQD4fY/f8KxNkdxpq+n7ryJaBU/93ZbBdYtfwIs1r437G9QJfZ1h1rgJeIjPd/MAD3Knb1Q50c0fsEl8cnuzp86mY+imfrU2QKaF4WQzoiMItwU=", "asset_tag_digest": "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "host_info": { "os_name": "RedHatEnterprise", "os_version": "8.1", "bios_version": "SE5C620.86B.00.01.6016.032720190737", "vmm_name": "Docker", "vmm_version": "19.03.5", "processor_info": "54 06 05 00 FF FB EB BF", "host_name": "computepurley1", "bios_name": "Intel Corporation", "hardware_uuid": "1ad9c003-b0e0-4319-b2b3-06053dfd1407", "process_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE", "no_of_sockets": "2", "tboot_installed": "true", "is_docker_env": "false", "hardware_features": { "TXT": { "enabled": "true" }, "TPM": { "enabled": "true", "meta": { "tpm_version": "2.0", "pcr_banks": "SHA1_SHA256" } } }, "installed_components": [ "tagent", "wlagent" ] }, "pcr_manifest": { "sha1pcrs": [ { "index": "pcr_0", "value": "6d73d0f4be74794317102e3f9a811fe00f373cc8", "pcr_bank": "SHA1" }, { "index": "pcr_1", "value": "c0b4764a706fd82f44dbd94b27bf1ede7019ca7b", "pcr_bank": "SHA1" }, { "index": "pcr_2", "value": "a196e9d4b283700303db501ed7279af6ec417e2d", "pcr_bank": "SHA1" }, { "index": "pcr_3", "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236", "pcr_bank": "SHA1" }, { "index": "pcr_18", "value": "86da61107994a14c0d154fd87ca509f82377aa30", "pcr_bank": "SHA1" }, { "index": "pcr_19", "value": "0000000000000000000000000000000000000000", "pcr_bank": "SHA1" }, { "index": "pcr_22", "value": "0000000000000000000000000000000000000000", "pcr_bank": "SHA1" } ], "sha2pcrs": [ { "index": "pcr_0", "value": "95a27f12d848b554f31760f3811b6091788769d08eee450ff6a7e323a02bc973", "pcr_bank": "SHA256" }, { "index": "pcr_1", "value": "1491222c41d2bd84c4ea91a331edf9bb5981f7475fca91ab476bea5294939fba", "pcr_bank": "SHA256" }, { "index": "pcr_2", "value": "0033ef74f1d62b9d95c641bfda24642bafb7a6b54d03d90655d7c5f9b1d47caf", "pcr_bank": "SHA256" }, { "index": "pcr_3", "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969", "pcr_bank": "SHA256" }, { "index": "pcr_18", "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75", "pcr_bank": "SHA256" }, { "index": "pcr_19", "value": "0000000000000000000000000000000000000000000000000000000000000000", "pcr_bank": "SHA256" }, { "index": "pcr_22", "value": "0000000000000000000000000000000000000000000000000000000000000000", "pcr_bank": "SHA256" } ], "pcr_event_log_map": { "SHA1": [ { "pcr_index": "pcr_17", "event_log": [ {"value": "7636dbbb8b8f40a9b7b7140e6da43e5bf2f531de", "label": "HASH_START", "info": { "ComponentName": "HASH_START", "EventName": "OpenSource.EventName" } }, {"value": "9dcd8ac722c21e60652f0961ad6fe31938c4cc8f", "label": "BIOSAC_REG_DATA", "info": { "ComponentName": "BIOSAC_REG_DATA", "EventName": "OpenSource.EventName" } }, {"value": "3c585604e87f855973731fea83e21fab9392d2fc", "label": "CPU_SCRTM_STAT", "info": { "ComponentName": "CPU_SCRTM_STAT", "EventName": "OpenSource.EventName" } }, {"value": "9069ca78e7450a285173431b3e52c5c25299e473", "label": "LCP_CONTROL_HASH", "info": { "ComponentName": "LCP_CONTROL_HASH", "EventName": "OpenSource.EventName" } }, {"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f", "label": "LCP_DETAILS_HASH", "info": { "ComponentName": "LCP_DETAILS_HASH", "EventName": "OpenSource.EventName" } }, {"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f", "label": "STM_HASH", "info": { "ComponentName": "STM_HASH", "EventName": "OpenSource.EventName" } }, {"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895", "label": "OSSINITDATA_CAP_HASH", "info": { "ComponentName": "OSSINITDATA_CAP_HASH", "EventName": "OpenSource.EventName" } }, {"value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e", "label": "MLE_HASH", "info": { "ComponentName": "MLE_HASH", "EventName": "OpenSource.EventName" } }, {"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6", "label": "NV_INFO_HASH", "info": { "ComponentName": "NV_INFO_HASH", "EventName": "OpenSource.EventName" } }, {"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a", "label": "tb_policy", "info": { "ComponentName": "tb_policy", "EventName": "OpenSource.EventName" } }, {"value": "5b870664c50ead0421e4a67514724759aa9a9d5b", "label": "vmlinuz", "info": { "ComponentName": "vmlinuz", "EventName": "OpenSource.EventName" } }, {"value": "f5fe4b87cd388943202e05442ebf0973c749cf3e", "label": "initrd", "info": { "ComponentName": "initrd", "EventName": "OpenSource.EventName" } } ], "pcr_bank": "SHA1" }, { "pcr_index": "pcr_18", "event_log": [ {"value": "a395b723712b3711a89c2bb5295386c0db85fe44", "label": "SINIT_PUBKEY_HASH", "info": { "ComponentName": "SINIT_PUBKEY_HASH", "EventName": "OpenSource.EventName" } }, {"value": "3c585604e87f855973731fea83e21fab9392d2fc", "label": "CPU_SCRTM_STAT", "info": { "ComponentName": "CPU_SCRTM_STAT", "EventName": "OpenSource.EventName" } }, {"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895", "label": "OSSINITDATA_CAP_HASH", "info": { "ComponentName": "OSSINITDATA_CAP_HASH", "EventName": "OpenSource.EventName" } }, {"value": "9069ca78e7450a285173431b3e52c5c25299e473", "label": "LCP_CONTROL_HASH", "info": { "ComponentName": "LCP_CONTROL_HASH", "EventName": "OpenSource.EventName" } }, {"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f", "label": "LCP_AUTHORITIES_HASH", "info": { "ComponentName": "LCP_AUTHORITIES_HASH", "EventName": "OpenSource.EventName" } }, {"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6", "label": "NV_INFO_HASH", "info": { "ComponentName": "NV_INFO_HASH", "EventName": "OpenSource.EventName" } }, {"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a", "label": "tb_policy", "info": { "ComponentName": "tb_policy", "EventName": "OpenSource.EventName" } } ], "pcr_bank": "SHA1" } ], "SHA256": [ { "pcr_index": "pcr_15", "event_log": [ {"value": "ddbb7fd2b4aa332b6645b07d75e0b0edf4baed5813f879829acdb32c83a0382d", "label": "ISecL_Default_Workload_Flavor_v1.0-b68fd1b2-e34f-4637-b3de-f9da6b7f6511", "info": { "ComponentName": "ISecL_Default_Workload_Flavor_v1.0-b68fd1b2-e34f-4637-b3de-f9da6b7f6511", "EventName": "OpenSource.EventName" } }, {"value": "1d1affd0a6d562848387ee3c36a14a8158a847fb1f32ee54c67b95ea16d4d9c5", "label": "ISecL_Default_Application_Flavor_v1.0_TPM2.0-c2e5999b-8083-4c7f-917d-e979190a4183", "info": { "ComponentName": "ISecL_Default_Application_Flavor_v1.0_TPM2.0-c2e5999b-8083-4c7f-917d-e979190a4183", "EventName": "OpenSource.EventName" } } ], "pcr_bank": "SHA256" }, { "pcr_index": "pcr_17", "event_log": [ {"value": "5d0220ffbceca9ca4e28215480c0280b1681328326c593743fa183f70ffbe834", "label": "HASH_START", "info": { "ComponentName": "HASH_START", "EventName": "OpenSource.EventName" } }, {"value": "893d8ebf029907725f7deb657e80f7589c4ee52cdffed44547cd315f378f48c6", "label": "BIOSAC_REG_DATA", "info": { "ComponentName": "BIOSAC_REG_DATA", "EventName": "OpenSource.EventName" } }, {"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450", "label": "CPU_SCRTM_STAT", "info": { "ComponentName": "CPU_SCRTM_STAT", "EventName": "OpenSource.EventName" } }, {"value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119", "label": "LCP_CONTROL_HASH", "info": { "ComponentName": "LCP_CONTROL_HASH", "EventName": "OpenSource.EventName" } }, {"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "label": "LCP_DETAILS_HASH", "info": { "ComponentName": "LCP_DETAILS_HASH", "EventName": "OpenSource.EventName" } }, {"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "label": "STM_HASH", "info": { "ComponentName": "STM_HASH", "EventName": "OpenSource.EventName" } }, {"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93", "label": "OSSINITDATA_CAP_HASH", "info": { "ComponentName": "OSSINITDATA_CAP_HASH", "EventName": "OpenSource.EventName" } }, {"value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186", "label": "MLE_HASH", "info": { "ComponentName": "MLE_HASH", "EventName": "OpenSource.EventName" } }, {"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b", "label": "NV_INFO_HASH", "info": { "ComponentName": "NV_INFO_HASH", "EventName": "OpenSource.EventName" } }, {"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67", "label": "tb_policy", "info": { "ComponentName": "tb_policy", "EventName": "OpenSource.EventName" } }, {"value": "348a6284f46123a913681d53a201c05750d4527483ceaa2a2adbc7dda52cf506", "label": "vmlinuz", "info": { "ComponentName": "vmlinuz", "EventName": "OpenSource.EventName" } }, {"value": "d018a266352fee8f1e9453bd6a3977bea33ea9ac79c84c240c6d7e29d93d0115", "label": "initrd", "info": { "ComponentName": "initrd", "EventName": "OpenSource.EventName" } } ], "pcr_bank": "SHA256" }, { "pcr_index": "pcr_18", "event_log": [ {"value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7", "label": "SINIT_PUBKEY_HASH", "info": { "ComponentName": "SINIT_PUBKEY_HASH", "EventName": "OpenSource.EventName" } }, {"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450", "label": "CPU_SCRTM_STAT", "info": { "ComponentName": "CPU_SCRTM_STAT", "EventName": "OpenSource.EventName" } }, {"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93", "label": "OSSINITDATA_CAP_HASH", "info": { "ComponentName": "OSSINITDATA_CAP_HASH", "EventName": "OpenSource.EventName" } }, {"value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119", "label": "LCP_CONTROL_HASH", "info": { "ComponentName": "LCP_CONTROL_HASH", "EventName": "OpenSource.EventName" } }, {"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "label": "LCP_AUTHORITIES_HASH", "info": { "ComponentName": "LCP_AUTHORITIES_HASH", "EventName": "OpenSource.EventName" } }, {"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b", "label": "NV_INFO_HASH", "info": { "ComponentName": "NV_INFO_HASH", "EventName": "OpenSource.EventName" } }, {"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67", "label": "tb_policy", "info": { "ComponentName": "tb_policy", "EventName": "OpenSource.EventName" } } ], "pcr_bank": "SHA256" } ] } }, "binding_key_certificate": "MIIFITCCA4mgAwIBAgIJAKrvQp6ScTi1MA0GCSqGSIb3DQEBDAUAMBsxGTAXBgNVBAMTEG10d2lsc29uLXBjYS1haWswHhcNMjAwNDE1MDgwMzE2WhcNMzAwNDEzMDgwMzE2WjAlMSMwIQYDVQQDDBpDTj1CaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANJgmnV3e9VBFxZqKQP1FszztRQ0JXAlhE6SEa+1c8oTPbEG83s8nfprQwEaH89WBVm3QOe+Pl+ZS01E3jZ0asFHqkicnXh8nyWcpPY8JKQ8qRJzC68rvw2zgMo1QZKg65enTRIEABO8uFZKqye7xubJZOnanDPMbprer+Q+brdm+muOrHbROmY18utVnY3IciOPC2Hv+IC+4xzcli9PlkUxsUnmNf9pz85sLt2lft6gun4aGMh2ute8YTL6ZLNZ8nvZN8T8+7/IV3/Pklz4qtMyFxtpHIP2UUxlptk6uTvjsS4Nnwt5YdTuYm4yWzIFB7SApQsDbB4WtyPW9oRcRhkCAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIFIDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAiAAs8+xFev3D2D4WG6PPhDWJey+Q/rVqgI3NYt79/YbizCwAEAP9VqgAAAAAANrGOAAAABgAAAAEBAAcAPgAMNgAAIgALta+AaKE5Tb3YIl7i/P+7tFLzXKZFlI+aWppdCEXJfw0AIgALScYOkvDeijOdoEy0phrYroOncXXSpNZ9M2JjdylBTlwwggEUBghVBIEFAwIpAQSCAQYAFAALAQBJQMBtwZmONe+QFGtDxzIrcHEg+NoQ8hQVpr+5Vt2knUAEon6gJgqz1gSWm0f0Q8TRzRVOutPxtNZMSvokbfHcdYyjmSwoIMATeK+YDieGuL+4w0ezg30lYjRukFOTxA2fw7arNkL7J/fiXGOAAUqDM+z7k4/y8bfRwBHZiN3uxbroR9SwiniPYmxUMLiIPLNMJVKdDMQLzA6z+PTSc8pxf1d78q7y/L+9OFfrThj+m6B4c5qWNHmZc37JG854QDP41FMJI9/Q1cQK6iZHapZPjTp9ikQuF+aegOxzVfcxeJI+wjkwqcGgeEfL+xFx2nhQ+1MSQrZ/uFiZhggdgqtQMA4GCFUEgQUDAikCBAIAADANBgkqhkiG9w0BAQwFAAOCAYEATBlbRClIKh5a7N0kcdEs94Z/5Vzrql8mizEe9/+xXd+Pp9ndyEGjrq3DSsMiOQyt0zQ39TGDzPOzuBQ5DG6A/w21MGVKGO1w15J7Wxzpez7Gd76HwXGHIiJnJZ5Llz9s7IWDqU5fIra/t4qWZzSxpZOVgpBe/9QzIVjgV44sXtjUahC7pnWusEPXa8kcLrdj+Y9EiMbuAldcDLmduRhDO/ex+StRs0b21BfF6sjCud5Md28r8W5/NEuXOqaKYWIFbGjD5qflCL2stEfbJFnIASiBS9dYYFAPj+fQWJzOTtxtk7lfAIz2PD3TJwHWD+HyMd5PsaHOnTw9GEKz3NDdmSc3juhnfi5RNIlFKAtYUjQ+HQjYvOhNOZTPB0S8U/91XV6ph0bTWdxJh6/KUt9jxnASapeVkoS18Q4K5sEmB/iHU0/HY56oDsrjRibX/sWfh9XG2eB3U8DlQkFtyVGvuuD3ym7cPirhVxTUiSOYa/Z6OJ04Gbaya4rWS7ZLBStD", "measurement_xmls": [ "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Workload_Flavor_v1.0\" Uuid=\"b68fd1b2-e34f-4637-b3de-f9da6b7f6511\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/workload-agent/bin\">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir><File Path=\"/opt/workload-agent/bin/wlagent\">ac8b967514f0a4c0ddcd87ee6cfdd03ffc5e5dd73598d40b8f6b6ef6dd606040a5fc31667908561093dd28317dfa1033</File><CumulativeHash>2ae673d241fed6e55d89e33a3ae8c6d127ed228e4afedfabfc2409c2d7bf51714d469786f948935c0b25c954904a2302</CumulativeHash></Measurement>", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Application_Flavor_v1.0_TPM2.0\" Uuid=\"c2e5999b-8083-4c7f-917d-e979190a4183\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/bin\">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/dracut_files\">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/initrd_hooks\">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/lib\">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/mkinitrd_files\">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir><File Path=\"/opt/tbootxm/bin/tpmextend\">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File><File Path=\"/opt/tbootxm/bin/measure\">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File><File Path=\"/opt/tbootxm/bin/configure_host.sh\">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File><File Path=\"/opt/tbootxm/bin/generate_initrd.sh\">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File><File Path=\"/opt/tbootxm/bin/measure_host\">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File><File Path=\"/opt/tbootxm/bin/tboot-xm-uninstall.sh\">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File><File Path=\"/opt/tbootxm/bin/functions.sh\">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File><File Path=\"/opt/tbootxm/dracut_files/check\">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File><File Path=\"/opt/tbootxm/dracut_files/install\">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File><File Path=\"/opt/tbootxm/dracut_files/module-setup.sh\">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File><File Path=\"/opt/tbootxm/lib/libwml.so\">56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378</File><File Path=\"/opt/tbootxm/lib/create_menuentry.pl\">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File><File Path=\"/opt/tbootxm/lib/update_menuentry.pl\">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File><File Path=\"/opt/tbootxm/lib/remove_menuentry.pl\">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File><File Path=\"/opt/tbootxm/initrd_hooks/tcb\">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File><File Path=\"/opt/tbootxm/mkinitrd_files/setup-measure_host.sh\">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><File Path=\"/opt/trustagent/bin/module_analysis.sh\">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File><File Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><File Path=\"/opt/trustagent/bin/module_analysis_da_tcg.sh\">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File><CumulativeHash>7425a5806dc8a5aacd508e4d6866655bf475947cc8bb630a03ff42b898ee8a7d8fd3ca71c3e1dacdc0f375bcbaf11efc</CumulativeHash></Measurement>"]}}`

func TestVerifier_CreateFlavorGroupReport(t *testing.T) {
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
	type args struct {
		hostId     uuid.UUID
		reqs       flvGrpHostTrustReqs
		hostData   *hvs.HostManifest
		trustCache hostTrustCache
	}
	var platform hvs.SignedFlavor
	json.Unmarshal([]byte(platformFlavor), &platform)
	var software hvs.SignedFlavor
	json.Unmarshal([]byte(softwareFlavor), &software)
	var hostStatus hvs.HostStatus
	json.Unmarshal([]byte(HostStatus1), hostStatus)

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    hvs.TrustReport
		wantErr bool
	}{
		{
			name: "Create flavor group report - trust cache is not empty",
			fields: fields{
				FlavorStore:    mocks.NewMockFlavorStore(),
				FlavorVerifier: &verify{errorStatus: "No error"},
				HostStore:      mocks.NewMockHostStore(),
			},
			args: args{
				hostData: &hostStatus.HostManifest,
				trustCache: hostTrustCache{
					trustedFlavors: map[uuid.UUID]*hvs.Flavor{platform.Flavor.Meta.ID: &platform.Flavor},
				},
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
			_, err := v.CreateFlavorGroupReport(tt.args.hostId, tt.args.reqs, tt.args.hostData, tt.args.trustCache)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.CreateFlavorGroupReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
