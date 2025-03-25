/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

//Flavors API request payload
// swagger:parameters FlavorCreateRequest
type FlavorCreateRequest struct {
	// in:body
	Body models.FlavorCreateRequest
}

// Flavors API response payload
// swagger:parameters Flavors
type SignedFlavor struct {
	// in:body
	Body hvs.SignedFlavor
}

// Flavors API response payload
// swagger:parameters SignedFlavorCollection
type SignedFlavorCollection struct {
	// in:body
	Body hvs.SignedFlavorCollection
}

// ---
//
// swagger:operation GET /flavors Flavors Search-Flavors
// ---
//
// description: |
//   A flavor is a set of measurements and metadata organized in a flexible format that allows for ease of further extension. The measurements included in the flavor pertain to various hardware, software and feature categories, and their respective metadata sections provide descriptive information.
//
//   The six current flavor categories:
//   PLATFORM, OS, ASSET_TAG, HOST_UNIQUE, IMA, SOFTWARE (See the product guide for a detailed explanation)
//
//   When a flavor is created, it is associated with a flavor group. This means that the measurements for that flavor type are deemed acceptable to obtain a trusted status. If a host, associated with the same flavor group, matches the measurements contained within that flavor, the host is trusted for that particular flavor category (dependent on the flavor group policy). Searches for Flavor records. The identifying parameter can be specified as query to search flavors which will return flavor collection as a result.
//
//   Searches for relevant flavors and returns the signed flavor collection consisting of all the associated flavors.
//   Returns - The serialized Signed FlavorCollection Go struct object that was retrieved.
//
// x-permissions: flavors:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Flavor ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: key
//   description: The key can be any “key” field from the meta description section of a flavor. The value can be any “value” of the specified key field in the flavor meta description section. Both key and value query parameters need to be specified.
//   in: query
//   type: string
//   required: false
// - name: value
//   description: The value of the key attribute in flavor description. When provided, key must be provided in query as well.
//   in: query
//   type: string
//   required: false
// - name: flavorgroupId
//   description: The flavor group ID. Returns all the flavors associated with the flavor group ID.
//   in: query
//   type: string
//   required: false
// - name: flavorParts
//   description: An array of flavor parts returns all the flavors associated with the flavor parts
//   in: query
//   type: string
//   required: false
// - name: limit
//   description: Limit of the number of items in a page.
//   in: query
//   type: integer
//   required: false
//   default: 1000
// - name: afterId
//   description: Next row id after which db must be queried
//   in: query
//   type: integer
//   required: false
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully searched and returned a signed flavor collection.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavorCollection"
//   '400':
//     description: Invalid search criteria provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors?id=f66ac31d-124d-418e-8200-2abf414a9adf
// x-sample-call-output: |
//     {
//        "signed_flavors": [
//        {
//            "flavor": {
//                "meta": {
//                    "schema": {
//                        "uri": "lib:wml:measurements:1.0"
//                    },
//                    "id": "f66ac31d-124d-418e-8200-2abf414a9adf",
//                    "description": {
//                        "flavor_part": "SOFTWARE",
//                        "label": "ISL_Applications",
//                        "digest_algorithm": "SHA384"
//                    }
//                },
//                "software": {
//                    "measurements": {
//                        "opt-trustagent-bin": {
//                            "type": "directoryMeasurementType",
//                            "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
//                            "Path": "/opt/trustagent/bin",
//                            "Include": ".*"
//                        },
//                        "opt-trustagent-bin-module_analysis_da.sh": {
//                            "type": "fileMeasurementType",
//                            "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
//                            "Path": "/opt/trustagent/bin/module_analysis_da.sh"
//                        }
//                    },
//                    "cumulative_hash": "be7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f"
//                }
//            },
//            "signature": "aas8/Nv7yYuwx2ZIOMrXFpNf333tBJgr87Dpo7Z5jjUR36Estlb8pYaTGN4Dz9JtbXZy2uIBLr1wjhkHVWm2r1FQq+2yJznXGCpkxWiQSZK84dmmr9tPxIxwxH5U/y8iYgSOnAdvWOn5E7tecil0WcYI/pDlXOs6WtsOWWDsHNXLswzw5qOhqU8WY/2ZVp0l1dnIFT17qQM9SOPi67Jdt75rMAqgl3gOmh9hygqa8KCmF7lrILv3u8ALxNyrqNqbInLGrWaHz5jSka1U+aF6ffmyPFUEmVwT3dp41kCNQshHor9wYo0nD1SAcls8EGZehM/xDokUCjUbfTJfTawYHgwGrXtWEpQVIPI+0xOtLK5NfUl/ZrQiJ9Vn95NQ0FYjfctuDJmlVjCTF/EXiAQmbEAh5WneGvXOzp6Ovp8SoJD5OWRuGhfaT7si3Z0KqGZ2Q6U0ppa8oJ3l4uPSfYlRdg4DFb4PyIScHSo93euQ6AnzGiMT7Tvk3e+lxymkNBwX"
//        }]
//     }

// ---

// swagger:operation POST /flavors Flavors Create-Flavors
// ---
//
// description: |
//   Creates new flavor(s) in database.
//   Flavors can be created by directly providing the flavor content in the request body, or they can be imported from a host. If the flavor content is provided, the flavor parameter must be set in the request. If the flavor is being imported from a host, the host connection string must be specified.
//
//   If a flavor group is not specified, the flavor(s) created will be assigned to the default “automatic” flavor group, with the exception of the host unique flavors, which are associated with the “host_unique” flavor group. If a flavor group is specified and does not already exist, it will be created with a default flavor match policy.
//
//   Partial flavor types can be specified as an array input. In this fashion, the user can choose which flavor types to import from a host. Only flavor types that are defined in the flavor group flavor match policy can be specified. If no partial flavor types are provided, the default action is to attempt retrieval of all flavor types. The response will contain all flavor types that it was able to create.
//
//   If generic flavors are created, all hosts in the flavor group will be added to the backend queue, flavor verification process to re-evaluate their trust status. If host unique flavors are created, the individual affected hosts are added to the flavor verification process.
//
//   The serialized FlavorCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute                      | Description                                     |
//    |--------------------------------|-------------------------------------------------|
//    | connection_string              | (Optional) The host connection string. flavorgroup_names, partial_flavor_types can be provided as optional parameters along with the host connection string. |
//    |                                | For INTEL hosts, this would have the vendor name, the IP addresses, or DNS host name and credentials i.e.: "intel:https://trustagent.server.com:1443 |
//    |                                | For VMware, this includes the vCenter and host IP address or DNS host name i.e.: "vmware:https://vCenterServer.com:443/sdk;h=host;u=vCenterUsername;p=vCenterPassword" |
//    | flavors                        | (Optional) A collection of flavors in the defined flavor format. No other parameters are needed in this case.
//    | signed_flavors                 | (Optional) This is collection of signed flavors consisting of flavor and signature provided by user. |
//    | flavorgroup_names              | (Optional) Flavor group names that the created flavor(s) will be associated with. If not provided, created flavor will be associated with automatic flavor group. |
//    | partial_flavor_types           | (Optional) List array input of flavor types to be imported from a host. Partial flavor type can be any of the following: PLATFORM, OS, ASSET_TAG, HOST_UNIQUE, IMA, SOFTWARE. Can be provided with the host connection string. See the product guide for more details on how flavor types are broken down for each host type. |
//
// x-permissions: flavors:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/FlavorCreateRequest"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: Successfully created the flavors.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavorCollection"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors
// x-sample-call-input: |
//      {
//          "connection_string" : "https://tagent-ip:1443/",
//          "partial_flavor_types" : ["OS", "PLATFORM"]
//      }
// x-sample-call-output: |
//    {
//     "signed_flavors": [
//         {
//             "flavor": {
//                 "meta": {
//                     "id": "1347c8a4-10ff-4cd4-81e6-75ec765a3be3",
//                     "description": {
//                         "bios_name": "Intel Corporation",
//                         "bios_version": "WLYDCRB1.SYS.0021.D02.2011260651",
//                         "cbnt_enabled": true,
//                         "flavor_part": "PLATFORM",
//                         "flavor_template_ids": [
//                             "48df0b29-9b05-485c-a005-8379aa2f4e5d",
//                             "0969de9f-8c84-4024-808e-8d87ab03e7f4",
//                             "9732b264-9a09-46d5-ad1d-dbf4a0028623"
//                         ],
//                         "label": "INTEL_IntelCorporation_WLYDCRB1.SYS.0021.D02.2011260651_CBNT_BTGP3_TPM_TXT_UEFI_SecureBootEnabled_2020-12-31T10:06:35.506222-05:00",
//                         "source": "wlr19s04",
//                         "suefi_enabled": true,
//                         "tboot_installed": false,
//                         "tpm_version": "2.0",
//                         "uefi_enabled": true,
//                         "vendor": "Linux"
//                     },
//                     "vendor": "INTEL"
//                 },
//                 "bios": {
//                     "bios_name": "Intel Corporation",
//                     "bios_version": "WLYDCRB1.SYS.0021.D02.2011260651"
//                 },
//                 "hardware": {
//                     "processor_info": "A6 06 06 00 FF FB EB BF",
//                     "processor_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
//                     "feature": {
//                         "TXT": {
//                             "enabled": true
//                         },
//                         "TPM": {
//                             "enabled": true,
//                             "version": "2.0",
//                             "pcr_banks": [
//                                 "SHA1",
//                                 "SHA256"
//                             ]
//                         },
//                         "CBNT": {
//                             "enabled": true,
//                             "profile": "BTGP3"
//                         },
//                         "SUEFI": {
//                             "enabled": true,
//                             "secure_boot_enabled": true
//                         }
//                     }
//                 },
//                 "pcrs": [
//                     {
//                         "pcr": {
//                             "index": 6,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "2989281f06f7a4aebd9c1a03869f91918ee7dfb2b4de64d6a0c80bd3a5db3bb5",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 0,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "6ff721e905c69ec83db8ae31bef0885982cab0d0c3b98c5e4eb18ceb2afbc354",
//                         "pcr_matches": true,
//                         "eventlog_equals": {
//                             "events": [
//                                 {
//                                     "type_id": "0x3",
//                                     "type_name": "EV_NO_ACTION",
//                                     "measurement": "0000000000000000000000000000000000000000000000000000000000000000"
//                                 },
//                                 {
//                                     "type_id": "0x7",
//                                     "type_name": "EV_S_CRTM_CONTENTS",
//                                     "tags": [
//                                         "Boot Guard Measured S-CRTM"
//                                     ],
//                                     "measurement": "240613f42068696ad49312f41f50e94f22d6801d1128450c425555e955a441f2"
//                                 },
//                                 {
//                                     "type_id": "0x8",
//                                     "type_name": "EV_S_CRTM_VERSION",
//                                     "measurement": "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
//                                 },
//                                 {
//                                     "type_id": "0x80000008",
//                                     "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB",
//                                     "measurement": "c4eefd2fc4037c299ef6270a12a23c62afcc79b41c243f4691a94f92f9ea8013"
//                                 },
//                                 {
//                                     "type_id": "0x80000008",
//                                     "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB",
//                                     "measurement": "2e3ffa3b146eab8ab958049f512a52342a51dc3bc0ccba2e06a98f8fbf92966b"
//                                 },
//                                 {
//                                     "type_id": "0x80000008",
//                                     "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB",
//                                     "measurement": "4b8f9e2b2a4f06fb132f325f2a36d6cd7cffa23382b243b0a597d989cf82769b"
//                                 },
//                                 {
//                                     "type_id": "0x80000008",
//                                     "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB",
//                                     "measurement": "c4eefd2fc4037c299ef6270a12a23c62afcc79b41c243f4691a94f92f9ea8013"
//                                 },
//                                 {
//                                     "type_id": "0x1",
//                                     "type_name": "EV_POST_CODE",
//                                     "tags": [
//                                         "ACPI DATA"
//                                     ],
//                                     "measurement": "3d13b2f22e51c24408ee29a1a423cceb48f045fddef8f4604f7b2dbe1692fb07"
//                                 },
//                                 {
//                                     "type_id": "0x1",
//                                     "type_name": "EV_POST_CODE",
//                                     "tags": [
//                                         "ACPI DATA"
//                                     ],
//                                     "measurement": "608072d8953921f15718897cbb0a47623e0c29fa7286d20beb0d733756acb643"
//                                 },
//                                 {
//                                     "type_id": "0x4",
//                                     "type_name": "EV_SEPARATOR",
//                                     "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
//                                 }
//                             ]
//                         }
//                     },
//                     {
//                         "pcr": {
//                             "index": 1,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "e2b734ab6ffa25d47efd9af408ecd7d601fd48e029299a090212c447eda02e17",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 2,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "bd66b5177062be02c57d7fd158a21e067bbb109a2be621010f858181a31a8420",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 3,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 4,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "02fd4da1758128c7a9fb8a2d0631c99f17bed3549950f7681522a763d0a87f53",
//                         "pcr_matches": true
//                     },
//                     {
//                         "pcr": {
//                             "index": 5,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "f2e236caadd0014f0f8b970547cbf36ca0cb248d16e4177b619db3594d782d53",
//                         "pcr_matches": true
//                     }
//                 ]
//             },
//             "signature": "kEzL48u9q9LrXKJJGmCKeg0U/ZFxCQ4OdZtUV0l9kE2tqYmEtzEmakEgUihiYjN72IMYXr/rbLbINRkByppp2ra2lExhtmoRk3FFZssl8LkjdpAzIIttjGZAwRjdeuyHBC69vSHQKIVtOd2rsruGjiS6QkqbJOGz1A6dI+zEEVI4f6dfeBoLnkJgZ2x8zjWpLbU8u4lN1npewQ9T4cYzw0mOJqZtdcjx8vuwwFJHSkMfIhEoZGaG/b/2+3eUvptbFAhrIVHWQXKjisC8qcl5+pjdao7jawJoY4kMw+3j6zCono2mS9buCfc2FHsuoqUMJw7Z/dHfmIwBVNKet5bWuxB4l6DpKJwk4FJUEpBpJbJPpmqgMgPNFX12fVQn+FJs8/KTsWfUHovIqggN0/ZYfCjG2YIBLgliZOEPH1zMnMReXwBUOQkenNLO81OL3iH89ePBAsKiCNTjM2Hi7pgAQpaWq+vDypGIQ5YshuBZiur94JtrY40FKUHVw78kjV9B"
//         },
//         {
//             "flavor": {
//                 "meta": {
//                     "id": "2e9d20f3-47a4-4adb-a930-dac4ed613911",
//                     "description": {
//                         "flavor_part": "OS",
//                         "flavor_template_ids": [
//                             "48df0b29-9b05-485c-a005-8379aa2f4e5d",
//                             "0969de9f-8c84-4024-808e-8d87ab03e7f4",
//                             "9732b264-9a09-46d5-ad1d-dbf4a0028623"
//                         ],
//                         "label": "INTEL_RedHatEnterprise_8.2_Virsh_4.5.0_2020-12-31T10:06:35.515548-05:00",
//                         "os_name": "RedHatEnterprise",
//                         "os_version": "8.2",
//                         "source": "wlr19s04",
//                         "tboot_installed": false,
//                         "tpm_version": "2.0",
//                         "uefi_enabled": true,
//                         "vendor": "Linux",
//                         "vmm_name": "Virsh",
//                         "vmm_version": "4.5.0"
//                     },
//                     "vendor": "INTEL"
//                 },
//                 "bios": {
//                     "bios_name": "Intel Corporation",
//                     "bios_version": "WLYDCRB1.SYS.0021.D02.2011260651"
//                 },
//                 "pcrs": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "measurement": "2989281f06f7a4aebd9c1a03869f91918ee7dfb2b4de64d6a0c80bd3a5db3bb5",
//                         "pcr_matches": true,
//                         "eventlog_includes": [
//                             {
//                                 "type_id": "0x80000001",
//                                 "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG",
//                                 "tags": [
//                                     "db"
//                                 ],
//                                 "measurement": "5f94ef49bd3a41f60c812aa76812461b670036687f70bc615e3fb78fdf3ac332"
//                             },
//                             {
//                                 "type_id": "0x800000e0",
//                                 "type_name": "EV_EFI_VARIABLE_AUTHORITY",
//                                 "tags": [
//                                     "db"
//                                 ],
//                                 "measurement": "e3d4866d84e25279442e3e5eb5d8f282093fba3331dc1c6f829310f642561e79"
//                             }
//                         ]
//                     }
//                 ]
//             },
//             "signature": "SndykHH3mrJxRerjWcH+HF6cy6r57G4qasgrSZY39DunMEkILkESfeync08KT/5nRYbx0yG7foNkYixL7PqfkYrxxjzlbs5oBQIw0j/uk/Tx+/6uMKGV0DDKscperYBiFIg8e3sC7LB34I8SAqBjpru714iiT+KQJ5qCMblJMSvvCij/R7whyMhRbhjlBYnSp9kcupTP6E5DIgoRRhbZgiAi/xFjMDN0KI4PGsTuxWnei95qku2i7c7lYwgtTUAPKYjKhuBlTpjHp6p/836D+h+AawUEPMrufFRgARlqbdl7h9snpdGJ9fJ7nQSdqBCejMEanX8ZQ3YGnRBRVQw2XR3iF+OABcTU0HMjmsix1VjVWhQW52czvQlZPSvp4Szm6al+U2jQbC/pI1Drinq6XyukHHoKN0OAuygmcJngQavTb3KhgyAYtWPKrNaZDDZN2MtdsJD1Mfx9CMVvB5TN1Kf/OWLElPtDZzygQtjNzaPoqYieg8HK3NttvCVyE4qj"
//         },
//    }

// ---

// swagger:operation GET /flavors/{flavor_id} Flavors Retrieve-Flavor
// ---
//
// description: |
//   Retrieves a flavor.
//   Returns - The serialized Signed Flavor Go struct object that was retrieved.
// x-permissions: flavors:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavor_id
//   description: Unique UUID of the Flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the flavor.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavor"
//   '404':
//     description: No flavor with the provided flavor ID found.
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors/f66ac31d-124d-418e-8200-2abf414a9adf
// x-sample-call-output: |
//  {
//    "flavor": {
//        "meta": {
//            "schema": {
//                "uri": "lib:wml:measurements:1.0"
//            },
//            "id": "f66ac31d-124d-418e-8200-2abf414a9adf",
//            "description": {
//                "flavor_part": "SOFTWARE",
//                "label": "ISL_Applications123",
//                "digest_algorithm": "SHA384"
//            }
//        },
//        "software": {
//            "measurements": {
//                "opt-trustagent-bin": {
//                    "type": "directoryMeasurementType",
//                    "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
//                    "Path": "/opt/trustagent/bin",
//                    "Include": ".*"
//                },
//                "opt-trustagent-bin-module_analysis_da.sh": {
//                    "type": "fileMeasurementType",
//                    "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
//                    "Path": "/opt/trustagent/bin/module_analysis_da.sh"
//                }
//            },
//            "cumulative_hash": "be7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f"
//        }
//    },
//    "signature": "aas8/Nv7yYuwx2ZIOMrXFpNf333tBJgr87Dpo7Z5jjUR36Estlb8pYaTGN4Dz9JtbXZy2uIBLr1wjhkHVWm2r1FQq+2yJznXGCpkxWiQSZK84dmmr9tPxIxwxH5U/y8iYgSOnAdvWOn5E7tecil0WcYI/pDlXOs6WtsOWWDsHNXLswzw5qOhqU8WY/2ZVp0l1dnIFT17qQM9SOPi67Jdt75rMAqgl3gOmh9hygqa8KCmF7lrILv3u8ALxNyrqNqbInLGrWaHz5jSka1U+aF6ffmyPFUEmVwT3dp41kCNQshHor9wYo0nD1SAcls8EGZehM/xDokUCjUbfTJfTawYHgwGrXtWEpQVIPI+0xOtLK5NfUl/ZrQiJ9Vn95NQ0FYjfctuDJmlVjCTF/EXiAQmbEAh5WneGvXOzp6Ovp8SoJD5OWRuGhfaT7si3Z0KqGZ2Q6U0ppa8oJ3l4uPSfYlRdg4DFb4PyIScHSo93euQ6AnzGiMT7Tvk3e+lxymkNBwX"
//  }

// ---

// swagger:operation DELETE /flavors/{flavor_id} Flavors Delete-Flavor
// ---
//
// description: |
//   Deletes a flavor.
// x-permissions: flavors:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavor_id
//   description: Unique UUID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the flavor.
//   '404':
//     description: No flavor with the provided flavor ID found.
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors/f66ac31d-124d-418e-8200-2abf414a9adf

// ---
