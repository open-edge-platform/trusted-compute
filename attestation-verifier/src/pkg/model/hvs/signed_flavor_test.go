/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// newSignedFlavorFromJSON returns an instance of SignedFlavor from an JSON string
func newSignedFlavorFromJSON(sfstring string) (*SignedFlavor, error) {
	var sf SignedFlavor
	err := json.Unmarshal([]byte(sfstring), &sf)
	if err != nil {
		fmt.Print(err)
		err = errors.Wrapf(err, "Error unmarshalling SignedFlavor JSON: %s", err.Error())
		return nil, err
	}

	return &sf, nil
}

const (
	goodSignedPlatformFlavor string = `{
        "flavor": {
            "meta": {
                "id": "09ebb703-93ff-4490-8c85-023c688b85f5",
                "description": {
                    "bios_name": "Intel Corporation",
                    "bios_version": "SE5C610.86B.01.01.0016.033120161139",
                    "cbnt_enabled": "true",
                    "flavor_Template_ID": [
                        "3cc60fc1-7bc0-4822-b932-40e13fae2ba4",
                        "fe20cb78-4584-4635-a674-e9af2a9e5f76",
                        "876593ef-4c1a-4519-9819-f069a319a653"
                    ],
                    "flavor_part": "PLATFORM",
                    "label": "INTEL_IntelCorporation_SE5C610.86B.01.01.0016.033120161139_TPM_TXT_2020-12-22T01:14:45.310921-08:00",
                    "source": "localhost.localdomain",
                    "tboot_installed": "true",
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
                        "enabled": "true"
                    },
                    "TPM": {
                        "enabled": "true",
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
        "signature": "hgOx/bMVjqPmHQ6MIgri8AZ1+zSOvS2CqPrRF+KPPxsl8kH68ZrFwSVdWRugFiTn+jIAX8sDiBjv19s9HSHsiFQdUSxck4qpul7I2UUfAfD23qNpBmKZpaXezuc/MRUIDT0ZQOQFOSvcPRBJtuFP9uLaV2k7WhCzDxegmCMBakM4SKTdwDtS5w/MwC1RYBjwlg8becJPN+Gi3goUvL3CkezJhRaUcyX/apty5YkxlWvxgcxo2p0JI06m7WxC/BzEjyH3TqlxoANUtXBnsf8qL5kJnvZF9O9vVoV0D4/PoRmiK25iNpqodDMZuHV5r7rhIpGiEMDvzkeQDKEYYogonP7w4HHBtJ+ZQOAVfgDmtI4iYXVs/NB4FtQGXVFIG24Gn2DUxG0VWPiI6xhJnr6uDX6hE8wsDeGY33Daw8dBXCZ8XhA8WJI1buR+3h5xJ9vre2JRyLjcPS80mP1tTI3COmp7lKsCiVxb2SduzGP2aw+2QEPjmtvxSLOhI2IbOypb"
    }
`
	goodSignedOSFlavor string = `{
        "flavor": {
            "meta": {
                "id": "fe0880be-4b8b-42b3-9b3f-a43313e102c2",
                "description": {
                    "flavor_Template_ID": [
                        "3cc60fc1-7bc0-4822-b932-40e13fae2ba4",
                        "fe20cb78-4584-4635-a674-e9af2a9e5f76",
                        "876593ef-4c1a-4519-9819-f069a319a653"
                    ],
                    "flavor_part": "OS",
                    "label": "INTEL_RedHatEnterprise_8.1___2020-12-22T01:14:45.325215-08:00",
                    "os_name": "RedHatEnterprise",
                    "os_version": "8.1",
                    "source": "localhost.localdomain",
                    "tboot_installed": "true",
                    "tpm_version": "2.0"
                },
                "vendor": "INTEL"
            },
            "bios": {
                "bios_name": "Intel Corporation",
                "bios_version": "SE5C610.86B.01.01.0016.033120161139"
            },
            "pcrs": [
                {
                    "pcr": {
                        "index": 17,
                        "bank": "SHA256"
                    },
                    "measurement": "8bc16f894471b5e53da2e799728d0187dae1951ef84ff95c347b7e53dab83695",
                    "pcr_matches": true
                }
            ]
        },
        "signature": "IN3E9JZGyBpGy8L7zPQceWzyOvJQIwZNox90xVKWjSRZhML7B7dlPGCVuhn4CYyO+aRpbHaAiV5Nr7gb+cmiq3olwyeFEHj3B2Yoj+mbGe/CgccfpRXVjFH3dbrR2twUpF0uzmWf5wbRFriaVstaubEtjV5FmcNNFeOhMLy4LWAC9H+qRrZlbMWfWGOEFFvOFmxLyXKlPmeeBENOumcMkHM8BrrSUyL0bhG7fBZtBQKisyFxupwwHFAiqtrv1c+N6B4D4tG5o9Q8we4+t2HBeO3xU67hFMBecBkpZtYCrKuXUZFBw2IURraS75ciR93HFkZNwU5TurM8gU5RpIUJA+sqOmAijXoGA8ajeoOnyydJFvt89bZ8hIEqtXUeArMV/hkwupWD+ravbbbfB4IfVkzl6QtSJwSzpP76GkBpP2cHAy4J2XKmU5uAx2KfkbMbSS2BG37Ej6RSEhbDv14sVli43rrCdshL9L99FvfH2IpeySJMc/WM1zL9IElcFxVL"
    }
`
	goodSignedHostUniqueFlavor string = `{
        "flavor": {
            "meta": {
                "id": "7d03d579-d586-49a7-853a-09b355f5380c",
                "description": {
                    "bios_name": "Intel Corporation",
                    "bios_version": "SE5C610.86B.01.01.0016.033120161139",
                    "flavor_Template_ID": [
                        "3cc60fc1-7bc0-4822-b932-40e13fae2ba4",
                        "fe20cb78-4584-4635-a674-e9af2a9e5f76",
                        "876593ef-4c1a-4519-9819-f069a319a653"
                    ],
                    "flavor_part": "HOST_UNIQUE",
                    "hardware_uuid": "0009e54e-642f-e511-906e-0012795d96dd",
                    "label": "INTEL_0009e54e-642f-e511-906e-0012795d96dd_2020-12-22T01:14:45.340084-08:00",
                    "os_name": "RedHatEnterprise",
                    "os_version": "8.1",
                    "source": "localhost.localdomain",
                    "tboot_installed": "true",
                    "tpm_version": "2.0"
                },
                "vendor": "INTEL"
            },
            "bios": {
                "bios_name": "Intel Corporation",
                "bios_version": "SE5C610.86B.01.01.0016.033120161139"
            },
            "pcrs": [
                {
                    "pcr": {
                        "index": 17,
                        "bank": "SHA256"
                    },
                    "measurement": "8bc16f894471b5e53da2e799728d0187dae1951ef84ff95c347b7e53dab83695",
                    "pcr_matches": true,
                    "eventlog_includes": [
                        {
                            "type_id": "0x40c",
                            "type_name": "LCP_CONTROL_HASH",
                            "tags": [
                                "LCP_CONTROL_HASH"
                            ],
                            "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
                        }
                    ]
                },
                {
                    "pcr": {
                        "index": 18,
                        "bank": "SHA256"
                    },
                    "measurement": "6f33d58a1fc09382042d2fd650f4c26af20cf2b18ea3bc0fdb075af2fa04f6d9",
                    "pcr_matches": true,
                    "eventlog_includes": [
                        {
                            "type_id": "0x40c",
                            "type_name": "LCP_CONTROL_HASH",
                            "tags": [
                                "LCP_CONTROL_HASH"
                            ],
                            "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
                        }
                    ]
                }
            ]
        },
        "signature": "JrjNxQuKEBaHLTTsQuMME64AqV3S/PbkX29zb2vTe9QArkNLR8dlAwqoh8xL6rw3DBqhbeZET8kyuR2ga7rgiuLpTATPeX4MqSP07fcuMuKzCY0tvKgkgw6z1X+9ZpZjrNNShorjAMvJyvuuuH0MTiBxu2U7DJsuNvIQQeq2KykNvYMWwvj9z9A5nmaTURFlB42JWlhUFxpusK5IeL5dipodEEPeoWYNu2j9eo0ayoqzsN4z0ju/P25onAqAjJJclw/HNvF0tDe1ypI4QBMrtCYB3GUADhgLeKzb/iT4rbFTZinqodk14+okb7njLVvd2pa/isEBvwx5zjoLnziTwISTEKeimsIV3x7OpXGUJzgBwgVm+TpfCOZPP6VT/w4PqgRM4IpGiCNtIFxe3T/g0jg/wPixoXFJ2zz0Ncn4eLayYCzt7cU8v7El/R9ETIrOetEUQrPNimf0QiW0+Cau2sFQrIkR8s2pbRXPlDEF94BwMnAJk26kakA1DDXwn2G+"
    }
    `
	goodSignedSoftwareFlavor string = `{
            "flavor": {
                "meta": {
                    "schema": {
                        "uri": "lib:wml:measurements:1.0"
                    },
                    "id": "c206e9c4-f394-42e5-a6aa-f28467eada3f",
                    "description": {
                        "flavor_part": "SOFTWARE",
                        "label": "ISecL_Default_Workload_Flavor_v1.0",
                        "digest_algorithm": "SHA384"
                    }
                },
                "software": {
                    "measurements": {
                        "opt-workload-agent-bin": {
                            "type": "directoryMeasurementType",
                            "value": "e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a",
                            "Path": "/opt/workload-agent/bin",
                            "Include": ".*",
                            "Exclude": ""
                        },
                        "opt-workload-agent-bin-wlagent": {
                            "type": "fileMeasurementType",
                            "value": "62adb091ca53d6907624fc564c686d614d10bb49396dad946dc9f0bec0fb14941a61dc375cf6fb314416305ea63a09c0",
                            "Path": "/opt/workload-agent/bin/wlagent"
                        }
                    },
                    "cumulative_hash": "4e8b4ac979106494f2707d7ce8ac11520144dce5459866ba5e0edc274875676e04c5e441699d76311d45aff1f8fd1e59"
                }
            },
            "signature": "kCb0j179THrSiIhglLzmSed84C4lvjSVBE4hdEThZ/6BheuUTvAB7Je4gGNRfnESgr4m8d/PPFIGQdY62AJl251oT6k6KaESPQCjPRq0EL9xfZBhksLA+42RcmEgIyIYZvtmx/9lWCZOmKZkT/0pYEW7VTgmUgFG33ah/JWL+peFfu4G1uaE4ZiOImPT3A6bybUKIglaNAZq75mGkRhSR63Gy81v4CRugrI+Oye6GeMh+A9PUJLb2sprVXqQPQc2ru1OqpkpARbi0Cj+12E6m29ZVPTL8IDlSkQbYlXL+eNaleISaHyKQ78mP0DotrPsBQNx3pSyRAAqJdlzRiP8mCjxWWOzcK9jcyakeYtAiqGEW6wG7OdBEcZlC6LWQd7OyKPu/dN14KK5q19+/haqhvsAs3dEJr4KKWhEzv23KksOMJTBQFXf1eRyY+SPL0UK9Bonpa6JyHlqaQ4wDQoJ0N6+CqQ9wLNnIBCNEtGHrbU9dWQnOo79qLKTOGCCEFsw"
        }`
)

var goodSignedAssetTagFlavor = `{
            "flavor": {
                "meta": {
                    "id": "a04e4818-450c-479c-bf8a-0510f9660c1d",
                    "description": {
                        "flavor_part": "ASSET_TAG",
                        "label": "INTEL_803F6068-06DA-E811-906E-00163566263E_03-18-2020_17-28-06",
                        "hardware_uuid": "803F6068-06DA-E811-906E-00163566263E"
                    },
                    "vendor": "INTEL"
                },
                "external": {
                    "asset_tag": {
                        "tag_certificate": {
                            "encoded": "MIIChTCB7gIBATAfoR2kGzAZMRcwFQYBaQQQgD9gaAba6BGQbgAWNWYmPqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXDwMKncMCIYDzIwMjAwMzE5MDAyODA1WhgPMjAyMTAzMTkwMDI4MDVaMGkwIAYFVQSGFQIxFzAVDAVTVEFURTAMDApDQUxJRk9STklBMBcGBVUEhhUCMQ4wDAwDVFBNMAUMAzIuMDAsBgVVBIYVAjEjMCEMCEhPU1ROQU1FMBUME20yM3J1Ni5mbS5pbnRlbC5jb20wDQYJKoZIhvcNAQEMBQADggGBAHKyvzsiRGUAECqqnT4KWuE6uF+chxJS+hkAUSth1MFu75HhNhMo3hOGyl1cfwzaL0d1kCMqNz0FlhH+XwT1maXR4BFkg9G/cdT4BgBhpcfiSSUuj0pUV0rH1NR1KD+DXdF0kenrOakg6hi350KX+9Y7qrfyF2YGUAKt4xrWZWpHDpHwW+Tvs68ZbcApvt4KBAsK3b+TV9DhePEF9u7NSHRnLZ/DR5BrrOIzDV0pGMOOHHYJGWmAVKOfpoGmipx1lTiDBCfxgEA4U0rIBu6mQjY1vMQu2vQi0aIaUtoUh+DfqgstaKjUA2KLymZ5OY+dl2weB+ZHpeJYnriBJmncOwENchNzGt26CGYE/cxXJR8axv4vaqggruMY3DJAv8rQWsJLTUA0nLk/90vIHfXWA7KSjJUKbSRfJvBu7tNAjrT0w4MWEGv8P0AmHDsoPEP77kAwqfdIo+72SZig8rDAlwLFxmcM4h7L5PjumwPJQG3g1aEitFAkaHBu2lsjZC652w==",
                            "issuer": "CN=asset-tag-service",
                            "serial_number": 1584577685980,
                            "subject": "803f6068-06da-e811-906e-00163566263e",
                            "not_before": "` + time.Now().Format(time.RFC3339) + `",
                            "not_after": "` + time.Now().AddDate(3, 0, 0).Format(time.RFC3339) + `",
                            "attribute": [
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                },
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                },
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                }
                            ],
                            "fingerprint_sha384": "rSHW/ijNPDapZkZ2FBsJXSWszHNa1RK3e2wdPJpBxTyoG2o9JJAJ4CbGF4bfTq/R"
                        }
                    }
                }
            },
            "signature": "kmiFgoWF5CZ6EDg/iz6NM1vzApYSdlmRblEZ9r76FHjhuYjqqyJTYEkxf1igFjEFIsJ3CmHVw1aPeUrncMnu+gvMfsJwfknOdhbDhqTyKtQBVNoMvrVGXV9kqkZvQ6OScev9nOcIQ/ahOUTV9TaRWbeulWMfheP32+4UZxUywWA3zpzvnjIKi7M0feWUZy5lV/ocOvaWYK8sYntsSi5ICEsLO63oKmT5RECxOPi/Pos9kmWkuzBzllytCvmDXpyswsCt5h1fmX1ytdC4vY37rcRozD/rSxw5RDH3pUR6h2GPVdrUDQ6VI7qOw2S73tZaTRJSMpZW9EVflTIbfUJC+Ft+y4rQ7cFQJDKOAppHYEv0AnB6Iy98n3M40ZPCB9qDYpNswq7ufBdaX2EADoYBc6QzsvcIEHNPyEw5QgkAjsj6ckGuhRg31KBPV0vw8Xjvmu+CnD+I1yKq9AVGdBqZZ66dUALP1Y/MJfP9vPPrRwiEx3IZcTKLftCiJVqIviEF"
        }`

func TestNewSignedFlavorFromJSONPlatform(t *testing.T) {
	type args struct {
		ipflavorjson string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Unmarshal Signed Platform flavor",
			args: args{
				ipflavorjson: goodSignedPlatformFlavor,
			},
		},
		{
			name: "Unmarshal Signed OS flavor",
			args: args{
				ipflavorjson: goodSignedOSFlavor,
			},
		},
		{
			name: "Unmarshal Signed Host Unique flavor",
			args: args{
				ipflavorjson: goodSignedHostUniqueFlavor,
			},
		},
		{
			name: "Unmarshal Signed Software flavor",
			args: args{
				ipflavorjson: goodSignedSoftwareFlavor,
			},
		},
		{
			name: "Unmarshal Signed Asset Tag flavor",
			args: args{
				ipflavorjson: goodSignedAssetTagFlavor,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unmarshal the flavor JSON
			got1, _ := newSignedFlavorFromJSON(tt.args.ipflavorjson)
			if got1 == nil {
				t.Errorf("SignedFlavor creation failed: %v", got1)
			}

			// Marshal flavor back to string
			strsf, err := json.Marshal(got1)
			if err != nil {
				t.Errorf("Error marshaling SignedFlavor to JSON: %s", err.Error())
			}

			// Perform unmarshal on the newly fetched string
			got2, _ := newSignedFlavorFromJSON(tt.args.ipflavorjson)
			if got1 == nil {
				t.Errorf("SignedFlavor creation failed: %v", got1)
			}

			assert.True(t, reflect.DeepEqual(got1, got2), "2-way model check failed")

			t.Logf("Before Unmarshal: %s\nAfter Marshal: %v\nAfter Marshal:%s", tt.args.ipflavorjson, got1, strsf)
		})
	}
}
