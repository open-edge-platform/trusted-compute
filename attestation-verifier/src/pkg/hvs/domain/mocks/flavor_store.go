/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"io/ioutil"
	"reflect"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockFlavorStore provides a mocked implementation of interface hvs.FlavorStore
type MockFlavorStore struct {
	flavorStore            []hvs.SignedFlavor
	FlavorFlavorGroupStore map[uuid.UUID][]uuid.UUID
	FlavorgroupStore       map[uuid.UUID]*hvs.FlavorGroup
}

var flavor = ` {
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

var LatestFlavor = `{
    "flavor": {
        "meta": {
            "id": "e6612219-bbd5-4259-8c7e-991e43729a86",
            "description": {
                "bios_name": "Intel Corporation",
                "bios_version": "SE5C610.86B.01.01.0016.033120161139",
                "cbnt_enabled": true,
                "flavor_Template_ID": [
                    "3cc60fc1-7bc0-4822-b932-40e13fae2ba4",
                    "fe20cb78-4584-4635-a674-e9af2a9e5f76",
                    "876593ef-4c1a-4519-9819-f069a319a653"
                ],
                "flavor_part": "PLATFORM",
                "label": "INTEL_IntelCorporation_SE5C610.86B.01.01.0016.033120161139_TPM_TXT_2020-12-21T23:07:40.999219-08:00",
                "source": "localhost.localdomain",
                "tboot_installed": true,
                "tpm_version": "2.0"
            },
            "vendor": "INTEL"
        },
        "bios": {
            "bios_name": "Intel Corporation",
            "bios_version": "SE5C610.86B.01.01.0016.033120161139"
        },
        "hardware": {
            "processor_info": "F1 06 04 00 FF FB EB BF",
            "processor_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
            "feature": {
                "TXT": {
                    "enabled": true
                },
                "TPM": {
                    "enabled": true,
                    "version": "2.0",
                    "pcr_banks": [
                        "SHA1",
                        "SHA256"
                    ]
                }
            }
        },
        "pcrs": [
            {
                "pcr": {
                    "index": 0,
                    "bank": "SHA256"
                },
                "measurement": "fad7981e1d16de3269667f4e84bf84a0a0c84f4f8a183e13ac5ba1c441bbfd3c",
                "pcr_matches": true
            },
            {
                "pcr": {
                    "index": 7,
                    "bank": "SHA256"
                },
                "measurement": "1d792e7db28fe00ca4a7e6ccb5bb28babf080a7ff11de3377240eee96c393fcc",
                "pcr_matches": true
            },
            {
                "pcr": {
                    "index": 17,
                    "bank": "SHA256"
                },
                "measurement": "8bc16f894471b5e53da2e799728d0187dae1951ef84ff95c347b7e53dab83695",
                "pcr_matches": true,
                "eventlog_equals": {
                    "events": [
                        {
                            "type_id": "0x402",
                            "type_name": "HASH_START",
                            "tags": [
                                "HASH_START"
                            ],
                            "measurement": "14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db"
                        },
                        {
                            "type_id": "0x40a",
                            "type_name": "BIOSAC_REG_DATA",
                            "tags": [
                                "BIOSAC_REG_DATA"
                            ],
                            "measurement": "c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428"
                        },
                        {
                            "type_id": "0x40b",
                            "type_name": "CPU_SCRTM_STAT",
                            "tags": [
                                "CPU_SCRTM_STAT"
                            ],
                            "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
                        },
                        {
                            "type_id": "0x412",
                            "type_name": "LCP_DETAILS_HASH",
                            "tags": [
                                "LCP_DETAILS_HASH"
                            ],
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
                        },
                        {
                            "type_id": "0x40e",
                            "type_name": "STM_HASH",
                            "tags": [
                                "STM_HASH"
                            ],
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
                        },
                        {
                            "type_id": "0x40f",
                            "type_name": "OSSINITDATA_CAP_HASH",
                            "tags": [
                                "OSSINITDATA_CAP_HASH"
                            ],
                            "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93"
                        },
                        {
                            "type_id": "0x404",
                            "type_name": "MLE_HASH",
                            "tags": [
                                "MLE_HASH"
                            ],
                            "measurement": "125f11bd4fb1156a29fbac5357ac04d14429c866a37d10643b1599be77917f82"
                        },
                        {
                            "type_id": "0x414",
                            "type_name": "NV_INFO_HASH",
                            "tags": [
                                "NV_INFO_HASH"
                            ],
                            "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
                        }
                    ],
                    "exclude_tags": [
                        "LCP_CONTROL_HASH",
                        "initrd",
                        "vmlinuz"
                    ]
                }
            },
            {
                "pcr": {
                    "index": 18,
                    "bank": "SHA256"
                },
                "measurement": "6f33d58a1fc09382042d2fd650f4c26af20cf2b18ea3bc0fdb075af2fa04f6d9",
                "pcr_matches": true,
                "eventlog_equals": {
                    "events": [
                        {
                            "type_id": "0x410",
                            "type_name": "SINIT_PUBKEY_HASH",
                            "tags": [
                                "SINIT_PUBKEY_HASH"
                            ],
                            "measurement": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7"
                        },
                        {
                            "type_id": "0x40b",
                            "type_name": "CPU_SCRTM_STAT",
                            "tags": [
                                "CPU_SCRTM_STAT"
                            ],
                            "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
                        },
                        {
                            "type_id": "0x40f",
                            "type_name": "OSSINITDATA_CAP_HASH",
                            "tags": [
                                "OSSINITDATA_CAP_HASH"
                            ],
                            "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93"
                        },
                        {
                            "type_id": "0x413",
                            "type_name": "LCP_AUTHORITIES_HASH",
                            "tags": [
                                "LCP_AUTHORITIES_HASH"
                            ],
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
                        },
                        {
                            "type_id": "0x414",
                            "type_name": "NV_INFO_HASH",
                            "tags": [
                                "NV_INFO_HASH"
                            ],
                            "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
                        }
                    ],
                    "exclude_tags": [
                        "LCP_CONTROL_HASH",
                        "initrd",
                        "vmlinuz"
                    ]
                }
            }
        ]
    },
    "signature": "TZty4EZSn3HRfeOv+7nZUY6+jxKQTRWIDP6aseSTsZ/+wD0pSbP5jYH3TNnbzG8v6eOw45U/qKZklMgQkFX7h6nS10dT0yRjCXgT+eUCNCsIrOSwjL8VW0i3Tlcc/8wRpohOaje6CZlnXZCaMmRdLEa8nfSIeH5ahyc5k2I2bjpdPWxCwoXhUB3zIWxr1mKJYEguexAjomfZ3F6UoWKQ1jO4UJaLtmvis37yVON97nsLPoXv1W1705hfFWNYeNlNbdQ/1hvIIjS1tW5LTujb48CGNLh8o7CowpH0QfGFnvufAuh4Pd1hDpT+2pjREuSgmPu9t7oMk4UmNUXUMPbsfClLutBe2bBxvwru9G48s0rsOpmErsnwhsFALHDIxrbt3vr+z83E5p4pigSJksItrWGQIrc1a/3ZOtA4SlWwALffWJdhyP89wQAAHIcGAyV9LFv0ywW4UFA0fv7d4rYjgyzTKzfCNCnjCjxwv0DIrBUZ6QdJMhXL0RHzj9fLGrB6"
}`

// Delete Flavor
func (store *MockFlavorStore) Delete(id uuid.UUID) error {
	for i, f := range store.flavorStore {
		if f.Flavor.Meta.ID == id {
			store.flavorStore[i] = hvs.SignedFlavor{}
			return nil
		}
	}
	return errors.New(commErr.RowsNotFound)
}

// Retrieve returns Flavor
func (store *MockFlavorStore) Retrieve(id uuid.UUID) (*hvs.SignedFlavor, error) {
	for _, f := range store.flavorStore {
		if f.Flavor.Meta.ID == id {
			return &f, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Search returns a filtered list of flavors per the provided FlavorFilterCriteria
func (store *MockFlavorStore) Search(criteria *models.FlavorVerificationFC) ([]hvs.SignedFlavor, error) {
	var sfs []hvs.SignedFlavor
	// flavor filter empty
	if criteria == nil {
		return store.flavorStore, nil
	}

	// return all entries
	if reflect.DeepEqual(*criteria, models.FlavorFilterCriteria{}) {
		return store.flavorStore, nil
	}

	var sfFiltered []hvs.SignedFlavor
	// Flavor ID filter
	if len(criteria.FlavorFC.Ids) > 0 {
		for _, f := range store.flavorStore {
			for _, id := range criteria.FlavorFC.Ids {
				if f.Flavor.Meta.ID == id {
					sfFiltered = append(sfFiltered, f)
					break
				}
			}
		}
		sfs = sfFiltered
	} else if criteria.FlavorFC.FlavorgroupID != uuid.Nil ||
		len(criteria.FlavorFC.FlavorParts) >= 1 || len(criteria.FlavorPartsWithLatest) >= 1 {
		flavorPartsWithLatestMap := getFlavorPartsWithLatestMap(criteria.FlavorFC.FlavorParts, criteria.FlavorPartsWithLatest)
		// Find flavors for given flavor group Id
		var fIds = store.FlavorFlavorGroupStore[criteria.FlavorFC.FlavorgroupID]

		// for each flavors check the flavor part in flavorPartsWithLatestMap is present
		for _, fId := range fIds {
			f, _ := store.Retrieve(fId)
			if f != nil {
				var flvrPart hvs.FlavorPartName
				err := (&flvrPart).Parse(f.Flavor.Meta.Description[hvs.FlavorPartDescription].(string))
				if err != nil {
					defaultLog.WithError(err).Errorf("Error parsing Flavor part")
				}
				if f, _ := store.Retrieve(fId); flavorPartsWithLatestMap[flvrPart] == true {
					sfs = append(sfs, *f)
				}
			}
		}
	} else if criteria.FlavorFC.Limit == 1 || criteria.FlavorFC.AfterId == 1 {
		sfs = store.flavorStore[:1]
	}
	return sfs, nil
}

// Create inserts a Flavor
func (store *MockFlavorStore) Create(sf *hvs.SignedFlavor) (*hvs.SignedFlavor, error) {
	//It is not right way to directly append the pointer, reference will be copied. Copy only the values.
	rec := hvs.SignedFlavor{
		Flavor:    sf.Flavor,
		Signature: sf.Signature,
	}
	store.flavorStore = append(store.flavorStore, rec)
	return sf, nil
}

// NewMockFlavorStore provides one dummy data for Flavors
func NewMockFlavorStore() *MockFlavorStore {
	store := &MockFlavorStore{}

	var sf hvs.SignedFlavor
	err := json.Unmarshal([]byte(flavor), &sf)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error unmarshalling flavor")
	}
	// add to store
	_, err = store.Create(&sf)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}

	var sf1 hvs.SignedFlavor
	err = json.Unmarshal([]byte(LatestFlavor), &sf1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error unmarshalling flavor")
	}

	// add to store
	_, err = store.Create(&sf1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}

	return store
}

func NewFakeFlavorStoreWithAllFlavors(flavorFilePath string) *MockFlavorStore {
	store := &MockFlavorStore{}
	var signedFlavors []hvs.SignedFlavor

	flavorsJSON, _ := ioutil.ReadFile(flavorFilePath)

	err := json.Unmarshal(flavorsJSON, &signedFlavors)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error unmarshalling flavor")
	}
	for _, flvr := range signedFlavors {
		_, err = store.Create(&flvr)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating Flavor")
		}
	}
	return store
}

func getFlavorPartsWithLatestMap(flavorParts []hvs.FlavorPartName, flavorPartsWithLatestMap map[hvs.FlavorPartName]bool) map[hvs.FlavorPartName]bool {
	if len(flavorParts) <= 0 {
		return flavorPartsWithLatestMap
	}
	if len(flavorPartsWithLatestMap) <= 0 {
		flavorPartsWithLatestMap = make(map[hvs.FlavorPartName]bool)
	}
	for _, flavorPart := range flavorParts {
		if _, ok := flavorPartsWithLatestMap[flavorPart]; !ok {
			flavorPartsWithLatestMap[flavorPart] = false
		}
	}

	return flavorPartsWithLatestMap
}
