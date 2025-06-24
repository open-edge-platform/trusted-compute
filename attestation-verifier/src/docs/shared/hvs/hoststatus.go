/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// HostStatus response payload
// swagger:parameters HostStatus
type HostStatus struct {
	// in:body
	Body hvs.HostStatus
}

// HostStatusCollection response payload
// swagger:parameters HostStatusCollection
type HostStatusCollection struct {
	// in:body
	Body hvs.HostStatusCollection
}

//  ---
//
//  swagger:operation GET /host-status HostStatuses SearchHostStatus
//  ---
//  description: |
//      Searches for HostStatus records.
//      Returns - The serialized HostStatusCollection Go struct object that was retrieved, which is a collection of serialized HostStatus Go struct objects.
//
//      <b>Note</b>
//      Only one identifying parameter can be specified. The parameters listed here are in the order of priority that will be evaluated.
//
//  x-permissions: host_status:search
//  security:
//    - bearerAuth: []
//  produces:
//    - application/json
//  parameters:
//    - name: id
//      description: HostStatus ID
//      in: query
//      type: string
//      format: uuid
//      required: false
//    - name: hostName
//      description: Host name.
//      in: query
//      type: string
//      required: false
//    - name: hostId
//      description: Host UUID
//      in: query
//      type: string
//      format: uuid
//      required: false
//    - name: limit
//      description: Limit of the number of items in a page.
//      in: query
//      type: integer
//      required: false
//      default: 1000
//    - name: afterId
//      description: Next row id after which db must be queried
//      in: query
//      type: integer
//      required: false
//    - name: hostHardwareId
//      description: Hardware UUID of host.
//      in: query
//      type: string
//      format: uuid
//      required: false
//    - name: hostStatus
//      description: Host connection state.
//      in: query
//      type: string
//      enum:
//        - invalid
//        - unknown
//        - connected
//        - queue
//        - connection_failure
//        - connection_timeout
//        - unauthorized
//        - aik_not_provisioned
//        - ec_not_present
//        - measured_launch_failure
//        - tpm_ownership_failure
//        - tpm_not_present
//        - unsupported_tpm
//      required: false
//    - name: fromDate
//      description: |
//        Filters HostStatus records created after this date.
//         date                                   Ex: fromDate=2006-01-02
//         date+time                              Ex: fromDate=2006-01-02 15:04:05
//         date+time(with milli seconds)          Ex: fromDate=2006-01-02T15:04:05.000Z
//         date+time(with micro seconds)          Ex: fromDate=2006-01-02T15:04:05.000000Z
//      in: query
//      type: string
//      format: date-time
//      required: false
//    - name: toDate
//      description: |
//        Filters HostStatus records created before this date.
//         date                                   Ex: fromDate=2006-01-02
//         date+time                              Ex: fromDate=2006-01-02 15:04:05
//         date+time(with milli seconds)          Ex: fromDate=2006-01-02T15:04:05.000Z
//         date+time(with micro seconds)          Ex: fromDate=2006-01-02T15:04:05.000000Z
//      in: query
//      type: string
//      format: date-time
//      required: false
//    - name: latestPerHost
//      description: Return only the latest status of HostStatus records if true. Else returns records from audit log entries.
//      in: query
//      type: boolean
//      default: true
//      required: false
//    - name: numberOfDays
//      description: Returns HostStatus records created since the past 'n' days. For an exact range, use `fromDate` and `toDate` instead.
//      in: query
//      type: integer
//      minimum: 1
//      required: false
//    - name: Accept
//      description: Accept header
//      in: header
//      type: string
//      required: true
//      enum:
//        - application/json
//  responses:
//    '200':
//      description: Successfully retrieved the HostStatus records. Also returned when no results are found.
//      content: application/json
//      schema:
//        $ref: "#/definitions/HostStatusCollection"
//    '400':
//      description: Invalid values for search criteria
//    '415':
//      description: Invalid Accept Header in Request
//    '500':
//      description: Internal server error
//
//  x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/host-status
//  x-sample-call-output: |
//    {
//      "host_status": [
//          {
//              "id": "055dd911-6e59-4374-9761-837250ad0113",
//              "host_id": "47a3b602-f321-4e03-b3b2-8f3ca3cde128",
//              "created": "2020-07-17T04:47:33.842636Z",
//              "status": {
//                  "host_state": "CONNECTED",
//                  "last_time_connected": "0001-01-01T00:00:00Z"
//              },
//              "host_manifest": {
//                  "aik_certificate": "MIIDTDCCAbSgAwIBAgIGAXF82oFMMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29uLXBjYS1haWswHhcNMjAwNDE1MDgwMDI2WhcNMzAwNDE1MDgwMDI2WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Ug7M15W3I3LejIOxZOiSvgXboF4+7TxvaY8BbzrNoyGbV8QfyCHjmdYHoyyzwvCUp9CB7wg1tb0btSLAqITLjFnUnTks28Sqz5tZW3et0O0X1fAsSnhJIc3vtkgxnxEIFOx2nsUDrEPXbdH1XOjSs5iRE7K45v2MzN9CO2QCwydPbUmgwauJNI3eQS5AZjF3eVnus9MMhTvYj4PNwbRj3jjuMH6OzJKX4bKeRPm05IHQcT/sEFoq5mShAmGyl+RkkRennIm5VIUnV99jm8mJvfZL3LA43kiHiOkvwiN0ImnDnNADP40IpothFFfIQEhr2L9CYUuUlq/BAkgt9epdwIDAQABozEwLzAtBgNVHREBAf8EIzAhgR8ACxj9Cf0C/f0bOXZ4QSn9JP1LQf13QWAZEV5Bsnz9MA0GCSqGSIb3DQEBCwUAA4IBgQA/SUjxvk2e6zgmTm5VhoV4WMmvvfZWZqEuKNnNB4lIkfySLuETTU7Jw1lc4skgr3KvxoftRM0099WVxhVwQMK/MarE7yNW7JQr2byNLoOrVm6FSkcRowrGFEnvFtC/qiGQ9JQTRkormIxDuPsaZWVjHMEuefEyq9T+hueTP5a1NDJmvtlXD2MjMjwEzeGf7R3TURmXt6tjMotbyO0/uv1n3Q79Wl/yWzb+bs9g5QlIlSrDGaxK7c7I7jGh0ee2gS2BOa/9iS59B9AS1TwACyj47yjFXoSQsvWqZ7XfPPzFVcFvvwtLRLeOzgIZhD+ZXutmY+smqDnkh/PB5BmXM/zDlae4QJ71rBGrmvVVj2cWGdaeZ19JivLLiBw0164yehTcpDzQzZQqyY4X+kX+fQD4fY/f8KxNkdxpq+n7ryJaBU/93ZbBdYtfwIs1r437G9QJfZ1h1rgJeIjPd/MAD3Knb1Q50c0fsEl8cnuzp86mY+imfrU2QKaF4WQzoiMItwU=",
//                  "asset_tag_digest": "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
//                  "host_info": {
//                      "os_name": "RedHatEnterprise",
//                      "os_version": "8.1",
//                      "bios_version": "SE5C620.86B.00.01.6016.032720190737",
//                      "vmm_name": "Docker",
//                      "vmm_version": "19.03.5",
//                      "processor_info": "54 06 05 00 FF FB EB BF",
//                      "host_name": "myhost",
//                      "bios_name": "Intel Corporation",
//                      "hardware_uuid": "1ad9c003-b0e0-4319-b2b3-06053dfd1407",
//                      "process_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
//                      "no_of_sockets": "2",
//                      "tboot_installed": "true",
//                      "hardware_features": {
//                          "TXT": {
//                              "enabled": "true"
//                          },
//                          "TPM": {
//                              "enabled": "true",
//                              "meta": {
//                                  "tpm_version": "2.0",
//                                  "pcr_banks": "SHA1_SHA256"
//                              }
//                          }
//                      },
//                      "installed_components": [
//                          "tagent",
//                          "wlagent"
//                      ]
//                  },
//                  "pcr_manifest": {
//                      "sha1pcrs": [
//                          {
//                              "index": "pcr_0",
//                              "value": "6d73d0f4be74794317102e3f9a811fe00f373cc8",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_1",
//                              "value": "c0b4764a706fd82f44dbd94b27bf1ede7019ca7b",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_2",
//                              "value": "a196e9d4b283700303db501ed7279af6ec417e2d",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_3",
//                              "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_18",
//                              "value": "86da61107994a14c0d154fd87ca509f82377aa30",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_19",
//                              "value": "0000000000000000000000000000000000000000",
//                              "pcr_bank": "SHA1"
//                          },
//                          {
//                              "index": "pcr_22",
//                              "value": "0000000000000000000000000000000000000000",
//                              "pcr_bank": "SHA1"
//                          }
//                      ],
//                      "sha2pcrs": [
//                          {
//                              "index": "pcr_0",
//                              "value": "95a27f12d848b554f31760f3811b6091788769d08eee450ff6a7e323a02bc973",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_1",
//                              "value": "1491222c41d2bd84c4ea91a331edf9bb5981f7475fca91ab476bea5294939fba",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_2",
//                              "value": "0033ef74f1d62b9d95c641bfda24642bafb7a6b54d03d90655d7c5f9b1d47caf",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_3",
//                              "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_18",
//                              "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_19",
//                              "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                              "pcr_bank": "SHA256"
//                          },
//                          {
//                              "index": "pcr_22",
//                              "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                              "pcr_bank": "SHA256"
//                          }
//                      ],
//                      "pcr_event_log_map": {
//                          "SHA1": [
//                              {
//                                  "pcr_index": "pcr_17",
//                                  "event_log": [
//                                      {
//                                          "value": "7636dbbb8b8f40a9b7b7140e6da43e5bf2f531de",
//                                          "label": "HASH_START",
//                                          "info": {
//                                              "ComponentName": "HASH_START",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "9dcd8ac722c21e60652f0961ad6fe31938c4cc8f",
//                                          "label": "BIOSAC_REG_DATA",
//                                          "info": {
//                                              "ComponentName": "BIOSAC_REG_DATA",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "3c585604e87f855973731fea83e21fab9392d2fc",
//                                          "label": "CPU_SCRTM_STAT",
//                                          "info": {
//                                              "ComponentName": "CPU_SCRTM_STAT",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                          "label": "LCP_CONTROL_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_CONTROL_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                          "label": "LCP_DETAILS_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_DETAILS_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                          "label": "STM_HASH",
//                                          "info": {
//                                              "ComponentName": "STM_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                                          "label": "OSSINITDATA_CAP_HASH",
//                                          "info": {
//                                              "ComponentName": "OSSINITDATA_CAP_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e",
//                                          "label": "MLE_HASH",
//                                          "info": {
//                                              "ComponentName": "MLE_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                                          "label": "NV_INFO_HASH",
//                                          "info": {
//                                              "ComponentName": "NV_INFO_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                                          "label": "tb_policy",
//                                          "info": {
//                                              "ComponentName": "tb_policy",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "5b870664c50ead0421e4a67514724759aa9a9d5b",
//                                          "label": "vmlinuz",
//                                          "info": {
//                                              "ComponentName": "vmlinuz",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "f5fe4b87cd388943202e05442ebf0973c749cf3e",
//                                          "label": "initrd",
//                                          "info": {
//                                              "ComponentName": "initrd",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      }
//                                  ],
//                                  "pcr_bank": "SHA1"
//                              },
//                              {
//                                  "pcr_index": "pcr_18",
//                                  "event_log": [
//                                      {
//                                          "value": "a395b723712b3711a89c2bb5295386c0db85fe44",
//                                          "label": "SINIT_PUBKEY_HASH",
//                                          "info": {
//                                              "ComponentName": "SINIT_PUBKEY_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "3c585604e87f855973731fea83e21fab9392d2fc",
//                                          "label": "CPU_SCRTM_STAT",
//                                          "info": {
//                                              "ComponentName": "CPU_SCRTM_STAT",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                                          "label": "OSSINITDATA_CAP_HASH",
//                                          "info": {
//                                              "ComponentName": "OSSINITDATA_CAP_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                          "label": "LCP_CONTROL_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_CONTROL_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                          "label": "LCP_AUTHORITIES_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_AUTHORITIES_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                                          "label": "NV_INFO_HASH",
//                                          "info": {
//                                              "ComponentName": "NV_INFO_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                      {
//                                          "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                                          "label": "tb_policy",
//                                          "info": {
//                                              "ComponentName": "tb_policy",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      }
//                                  ],
//                                  "pcr_bank": "SHA1"
//                              }
//                          ],
//                          "SHA256": [
//                              {
//                                  "pcr_index": "pcr_15",
//                                  "event_log": [
//                                     {
//                                          "value": "ddbb7fd2b4aa332b6645b07d75e0b0edf4baed5813f879829acdb32c83a0382d",
//                                          "label": "ISecL_Default_Workload_Flavor_v1.0-b68fd1b2-e34f-4637-b3de-f9da6b7f6511",
//                                          "info": {
//                                              "ComponentName": "ISecL_Default_Workload_Flavor_v1.0-b68fd1b2-e34f-4637-b3de-f9da6b7f6511",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "1d1affd0a6d562848387ee3c36a14a8158a847fb1f32ee54c67b95ea16d4d9c5",
//                                          "label": "ISecL_Default_Application_Flavor_v1.0_TPM2.0-c2e5999b-8083-4c7f-917d-e979190a4183",
//                                          "info": {
//                                              "ComponentName": "ISecL_Default_Application_Flavor_v1.0_TPM2.0-c2e5999b-8083-4c7f-917d-e979190a4183",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      }
//                                  ],
//                                  "pcr_bank": "SHA256"
//                              },
//                              {
//                                  "pcr_index": "pcr_17",
//                                  "event_log": [
//                                     {
//                                          "value": "5d0220ffbceca9ca4e28215480c0280b1681328326c593743fa183f70ffbe834",
//                                          "label": "HASH_START",
//                                          "info": {
//                                              "ComponentName": "HASH_START",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "893d8ebf029907725f7deb657e80f7589c4ee52cdffed44547cd315f378f48c6",
//                                          "label": "BIOSAC_REG_DATA",
//                                          "info": {
//                                              "ComponentName": "BIOSAC_REG_DATA",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                                          "label": "CPU_SCRTM_STAT",
//                                          "info": {
//                                              "ComponentName": "CPU_SCRTM_STAT",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                          "label": "LCP_CONTROL_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_CONTROL_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                          "label": "LCP_DETAILS_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_DETAILS_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                          "label": "STM_HASH",
//                                          "info": {
//                                              "ComponentName": "STM_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                                          "label": "OSSINITDATA_CAP_HASH",
//                                          "info": {
//                                              "ComponentName": "OSSINITDATA_CAP_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186",
//                                          "label": "MLE_HASH",
//                                          "info": {
//                                              "ComponentName": "MLE_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                                          "label": "NV_INFO_HASH",
//                                          "info": {
//                                              "ComponentName": "NV_INFO_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                                          "label": "tb_policy",
//                                          "info": {
//                                              "ComponentName": "tb_policy",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "348a6284f46123a913681d53a201c05750d4527483ceaa2a2adbc7dda52cf506",
//                                          "label": "vmlinuz",
//                                          "info": {
//                                              "ComponentName": "vmlinuz",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "d018a266352fee8f1e9453bd6a3977bea33ea9ac79c84c240c6d7e29d93d0115",
//                                          "label": "initrd",
//                                          "info": {
//                                              "ComponentName": "initrd",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      }
//                                  ],
//                                  "pcr_bank": "SHA256"
//                              },
//                              {
//                                  "pcr_index": "pcr_18",
//                                  "event_log": [
//                                     {
//                                          "value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
//                                          "label": "SINIT_PUBKEY_HASH",
//                                          "info": {
//                                              "ComponentName": "SINIT_PUBKEY_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                                          "label": "CPU_SCRTM_STAT",
//                                          "info": {
//                                              "ComponentName": "CPU_SCRTM_STAT",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                                          "label": "OSSINITDATA_CAP_HASH",
//                                          "info": {
//                                              "ComponentName": "OSSINITDATA_CAP_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                          "label": "LCP_CONTROL_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_CONTROL_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                          "label": "LCP_AUTHORITIES_HASH",
//                                          "info": {
//                                              "ComponentName": "LCP_AUTHORITIES_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                                          "label": "NV_INFO_HASH",
//                                          "info": {
//                                              "ComponentName": "NV_INFO_HASH",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      },
//                                     {
//                                          "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                                          "label": "tb_policy",
//                                          "info": {
//                                              "ComponentName": "tb_policy",
//                                              "EventName": "OpenSource.EventName"
//                                          }
//                                      }
//                                  ],
//                                  "pcr_bank": "SHA256"
//                              }
//                          ]
//                      }
//                  },
//                  "binding_key_certificate": "MIIFITCCA4mgAwIBAgIJAKrvQp6ScTi1MA0GCSqGSIb3DQEBDAUAMBsxGTAXBgNVBAMTEG10d2lsc29uLXBjYS1haWswHhcNMjAwNDE1MDgwMzE2WhcNMzAwNDEzMDgwMzE2WjAlMSMwIQYDVQQDDBpDTj1CaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANJgmnV3e9VBFxZqKQP1FszztRQ0JXAlhE6SEa+1c8oTPbEG83s8nfprQwEaH89WBVm3QOe+Pl+ZS01E3jZ0asFHqkicnXh8nyWcpPY8JKQ8qRJzC68rvw2zgMo1QZKg65enTRIEABO8uFZKqye7xubJZOnanDPMbprer+Q+brdm+muOrHbROmY18utVnY3IciOPC2Hv+IC+4xzcli9PlkUxsUnmNf9pz85sLt2lft6gun4aGMh2ute8YTL6ZLNZ8nvZN8T8+7/IV3/Pklz4qtMyFxtpHIP2UUxlptk6uTvjsS4Nnwt5YdTuYm4yWzIFB7SApQsDbB4WtyPW9oRcRhkCAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIFIDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAiAAs8+xFev3D2D4WG6PPhDWJey+Q/rVqgI3NYt79/YbizCwAEAP9VqgAAAAAANrGOAAAABgAAAAEBAAcAPgAMNgAAIgALta+AaKE5Tb3YIl7i/P+7tFLzXKZFlI+aWppdCEXJfw0AIgALScYOkvDeijOdoEy0phrYroOncXXSpNZ9M2JjdylBTlwwggEUBghVBIEFAwIpAQSCAQYAFAALAQBJQMBtwZmONe+QFGtDxzIrcHEg+NoQ8hQVpr+5Vt2knUAEon6gJgqz1gSWm0f0Q8TRzRVOutPxtNZMSvokbfHcdYyjmSwoIMATeK+YDieGuL+4w0ezg30lYjRukFOTxA2fw7arNkL7J/fiXGOAAUqDM+z7k4/y8bfRwBHZiN3uxbroR9SwiniPYmxUMLiIPLNMJVKdDMQLzA6z+PTSc8pxf1d78q7y/L+9OFfrThj+m6B4c5qWNHmZc37JG854QDP41FMJI9/Q1cQK6iZHapZPjTp9ikQuF+aegOxzVfcxeJI+wjkwqcGgeEfL+xFx2nhQ+1MSQrZ/uFiZhggdgqtQMA4GCFUEgQUDAikCBAIAADANBgkqhkiG9w0BAQwFAAOCAYEATBlbRClIKh5a7N0kcdEs94Z/5Vzrql8mizEe9/+xXd+Pp9ndyEGjrq3DSsMiOQyt0zQ39TGDzPOzuBQ5DG6A/w21MGVKGO1w15J7Wxzpez7Gd76HwXGHIiJnJZ5Llz9s7IWDqU5fIra/t4qWZzSxpZOVgpBe/9QzIVjgV44sXtjUahC7pnWusEPXa8kcLrdj+Y9EiMbuAldcDLmduRhDO/ex+StRs0b21BfF6sjCud5Md28r8W5/NEuXOqaKYWIFbGjD5qflCL2stEfbJFnIASiBS9dYYFAPj+fQWJzOTtxtk7lfAIz2PD3TJwHWD+HyMd5PsaHOnTw9GEKz3NDdmSc3juhnfi5RNIlFKAtYUjQ+HQjYvOhNOZTPB0S8U/91XV6ph0bTWdxJh6/KUt9jxnASapeVkoS18Q4K5sEmB/iHU0/HY56oDsrjRibX/sWfh9XG2eB3U8DlQkFtyVGvuuD3ym7cPirhVxTUiSOYa/Z6OJ04Gbaya4rWS7ZLBStD",
//                  "measurement_xmls": [
//                      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Workload_Flavor_v1.0\" Uuid=\"b68fd1b2-e34f-4637-b3de-f9da6b7f6511\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/workload-agent/bin\">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir><File Path=\"/opt/workload-agent/bin/wlagent\">ac8b967514f0a4c0ddcd87ee6cfdd03ffc5e5dd73598d40b8f6b6ef6dd606040a5fc31667908561093dd28317dfa1033</File><CumulativeHash>2ae673d241fed6e55d89e33a3ae8c6d127ed228e4afedfabfc2409c2d7bf51714d469786f948935c0b25c954904a2302</CumulativeHash></Measurement>",
//                      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Application_Flavor_v1.0_TPM2.0\" Uuid=\"c2e5999b-8083-4c7f-917d-e979190a4183\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/bin\">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/dracut_files\">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/initrd_hooks\">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/lib\">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/mkinitrd_files\">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir><File Path=\"/opt/tbootxm/bin/tpmextend\">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File><File Path=\"/opt/tbootxm/bin/measure\">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File><File Path=\"/opt/tbootxm/bin/configure_host.sh\">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File><File Path=\"/opt/tbootxm/bin/generate_initrd.sh\">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File><File Path=\"/opt/tbootxm/bin/measure_host\">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File><File Path=\"/opt/tbootxm/bin/tboot-xm-uninstall.sh\">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File><File Path=\"/opt/tbootxm/bin/functions.sh\">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File><File Path=\"/opt/tbootxm/dracut_files/check\">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File><File Path=\"/opt/tbootxm/dracut_files/install\">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File><File Path=\"/opt/tbootxm/dracut_files/module-setup.sh\">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File><File Path=\"/opt/tbootxm/lib/libwml.so\">56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378</File><File Path=\"/opt/tbootxm/lib/create_menuentry.pl\">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File><File Path=\"/opt/tbootxm/lib/update_menuentry.pl\">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File><File Path=\"/opt/tbootxm/lib/remove_menuentry.pl\">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File><File Path=\"/opt/tbootxm/initrd_hooks/tcb\">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File><File Path=\"/opt/tbootxm/mkinitrd_files/setup-measure_host.sh\">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><File Path=\"/opt/trustagent/bin/module_analysis.sh\">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File><File Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><File Path=\"/opt/trustagent/bin/module_analysis_da_tcg.sh\">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File><CumulativeHash>7425a5806dc8a5aacd508e4d6866655bf475947cc8bb630a03ff42b898ee8a7d8fd3ca71c3e1dacdc0f375bcbaf11efc</CumulativeHash></Measurement>"
//                  ]
//              }
//          }
//      ]
//    }
//  ---

//  ---
//
//  swagger:operation GET /host-status/{hoststatus_id} HostStatuses RetrieveHostStatus
//  ---
//  description: |
//    This API is used to retrieve an individual HostStatus record.
//
//    A host status gives the current state of a host. When a host is registered or created, the backend queue, flavor verification
//    process is initiated for that host, and a connection is attempted to the host. Other activities will also automatically trigger
//    backend queue flavor verifications which may force connections to the host.
//    If a successful connection is made, the host status will reflect a CONNECTED state and include the host manifest.
//
//    The host manifest contains information collected from the host that is used to verify the host against respective flavors
//    within the host’s associated flavor group.
//
//    If the connection fails or a problem occurs when attempting to retrieve the required information from the host, the host status will
//    reflect an error state.
//
//    Below is a list of applicable Host States:
//    | Host State                     | Description                                     |
//    |--------------------------------|-------------------------------------------------|
//    | CONNECTED                      | Host is in a good, connected state |
//    | QUEUE                          | Host is currently in the flavor verification queue  |
//    | CONNECTION_FAILURE             | A connection failure occurred  |
//    | UNAUTHORIZED                   | The Host Verification Service is NOT authorized to access the host  |
//    | AIK_NOT_PROVISIONED            | Host AIK certificate is not provisioned  |
//    | EC_NOT_PRESENT                 | Host Endorsement Certificate (EC) is not present  |
//    | MEASURED_LAUNCH_FAILURE        | Host failed to launch TXT  |
//    | TPM_OWNERSHIP_FAILURE          |  Host agent does not have TPM ownership  |
//    | TPM_NOT_PRESENT                |  No TPM exists on the host  |
//    | UNSUPPORTED_TPM                |  Host TPM version is unsupported  |
//    | UNKNOWN                        |  Host is in unknown state  |
//
//    Returns - The serialized Host Go struct object that was retrieved.
//
//  x-permissions: host_status:retrieve
//  security:
//    - bearerAuth: []
//  produces:
//    - application/json
//  parameters:
//    - name: hoststatus_id
//      description: Unique ID of the HostStatus record.
//      in: path
//      required: true
//      type: string
//      format: uuid
//    - name: Accept
//      description: Accept header
//      in: header
//      type: string
//      required: true
//      enum:
//        - application/json
//  responses:
//    '200':
//      description: Successfully retrieved the HostStatus record.
//      content: application/json
//      schema:
//        $ref: "#/definitions/HostStatus"
//    '404':
//      description: HostStatus record not found
//    '415':
//      description: Invalid Accept Header in Request
//    '500':
//      description: Internal server error
//
//  x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/host-status/055dd911-6e59-4374-9761-837250ad0113
//  x-sample-call-output: |
//    {
//        "id": "06f9d8c6-0102-49e6-ae7a-0455de25f282",
//        "host_id": "91b022fc-3f9b-4269-999c-b39af2eac1eb",
//        "created": "2020-07-20T13:52:25.84078Z",
//        "status": {
//            "host_state": "CONNECTED",
//            "last_time_connected": "2020-07-20T06:52:25.840740767-07:00"
//        },
//        "host_manifest": {
//            "aik_certificate": "MIIDLzCCAZegAwIBAgIRAN+l/AlQRBLsXNHOJ4lxh8gwDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjAwNzIwMTM0NzQzWhcNMjUwNzIwMTM0NzQzWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlVfaCXwhDrp61SyHCCibvsMnsEMsm5NE679e9alFmDPzQFSNyzfcUkx1FYtpmEde/f4lKmupTkQYGhhSDoS3haPEn6W1s6zBKc9WZwrdViRRJvku0tbtZ2NgCxmP/dTQ0jdWfHd7i1/DNmx1L/vyVp+Cf1Dvk0/y7mEJXoCuL2x4sz0rvaru0Qb/THBX/h+bZiUMrmGvldcxMzuWNBGA+bYZ9rch8g6z5JR9XsnC46ssE7g2jidBccmka8GMMn/lAnismTnL8mRWNOa8Uq5VtdlVPFkoM02eIg54N7TJZpVPxIUducfJGF2GP9nI9Nz+1+Zz275Cq1lC+gA+QKvOkwIDAQABowIwADANBgkqhkiG9w0BAQsFAAOCAYEAqdx0uH3VX9U/Rh/JdYdlGTPsD6B6En/2SI92gKVVDC8bYolB5etZIocJpc8385XNMXbA8WX8lFxws12KeB6bdFXuN/wtpJWMbuFnsb7/QPB4C+NznZFjRebxmTmNOZMhBKwhGRDVkevaPV/uFJcXqI0f10lKDiZjG4I2t3y0DJJMTAIg9mz6h7BGGnhmdyfLWwR56bHnJGO7t5tz7nBfbUhJ7KTBjRHyb0G1DUiT2DOit8+V0eRWmqsPk0hQAL0WzR93Ckw/wWWvM32OV768XKWKFPHNYeZIQRZglejg/PjYOU2ppz0w5M0Z/CzY3aRrwX0rkC9CqKWgkzwQrElk1sU6hE9DQh+uw9KdN2rtZ3urTLRVRD6ojqwyznl8gJ2uq6G92HGEPzq9orLLxNIcXtMrJeHsXK3r5zyos8s2fHLjR9A2Bqg/gK7QzzEJzbUoHvjp/i86Xs5jiwvwY7dE3SSLwjIbhxgCKZ6j2CKAKxmaZVbHurh3nPsgruQ/WnDG",
//            "asset_tag_digest": "l2m29vWCZmwLFAhHE9P3XlN/xXbC6hNQeFiV/7INjMvier/4h04HYyeDaaL4iTxu",
//            "host_info": {
//                "os_name": "RedHatEnterprise",
//                "os_version": "8.1",
//                "bios_version": "SE5C620.86B.00.01.0015.110720180833",
//                "vmm_name": "Virsh",
//                "vmm_version": "4.5.0",
//                "processor_info": "54 06 05 00 FF FB EB BF",
//                "host_name": "myhost2",
//                "bios_name": "Intel Corporation",
//                "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//                "process_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
//                "no_of_sockets": "2",
//                "tboot_installed": "true",
//                "hardware_features": {
//                    "TXT": {
//                        "enabled": "true"
//                    },
//                    "TPM": {
//                        "enabled": "true",
//                        "meta": {
//                            "tpm_version": "2.0",
//                            "pcr_banks": "SHA1_SHA256"
//                        }
//                    }
//                },
//                "installed_components": [
//                    "tagent",
//                    "wlagent"
//                ]
//            },
//            "pcr_manifest": {
//                "sha1pcrs": [
//                    {
//                        "index": "pcr_0",
//                        "value": "d1f5a8283c75db86938aef334ba11ed4ff613a4e",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_1",
//                        "value": "58c94d1d346ade551354b585a771d734d50cd187",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_2",
//                        "value": "63311d0a7e2b22dd18554946a39776645c9d20ef",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_3",
//                        "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_4",
//                        "value": "45e5d65ceb021729f860b2bea40a8679e0a69dda",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_5",
//                        "value": "e397ec446342c88fde23940025dc00d07089b015",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_6",
//                        "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_7",
//                        "value": "518bd167271fbb64589c61e43d8c0165861431d8",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_8",
//                        "value": "b45858058ced5e553558c6ebee9b04c5fb678ce5",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_9",
//                        "value": "b049d9f5b64eaa1ba64576c5c5ead28bae8200c5",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_10",
//                        "value": "e4276735b646ac12f950848faa5dfc5fa3f2559d",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_11",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_12",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_13",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_14",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_15",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_16",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_17",
//                        "value": "fd9341534c3fbe2eccf5904e42822a3dd2e7dc67",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_18",
//                        "value": "86da61107994a14c0d154fd87ca509f82377aa30",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_19",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_20",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_21",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_22",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    },
//                    {
//                        "index": "pcr_23",
//                        "value": "0000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA1"
//                    }
//                ],
//                "sha2pcrs": [
//                    {
//                        "index": "pcr_0",
//                        "value": "d19f11e851d901297961e6a85e934c3baa27faeaa3f47d3288e90b480091d12d",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_1",
//                        "value": "3fdda2b900db244d8192089bddddb272b2879efde2ae9a9e4bc590a52866e4e6",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_2",
//                        "value": "352b1c6afdc287cc95a563d0f04ed43491fd94f1599f62b0b91b20194873f104",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_3",
//                        "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_4",
//                        "value": "8570fd50e3c21aa17ab3d777de5e24c6e5dcb94f198db1430e76c0f8d845a16c",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_5",
//                        "value": "3f7117f945335ff6cee453ff88f2794fef44c6185124344c88e25265a1aa9c74",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_6",
//                        "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_7",
//                        "value": "65caf8dd1e0ea7a6347b635d2b379c93b9a1351edc2afc3ecda700e534eb3068",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_8",
//                        "value": "df25ce52349e168ce827d76c154b697828db6a646662dcd79111a869ec5a805f",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_9",
//                        "value": "6a6832ae313339d01a7a647f574078ac1467bb9f4b25269d55da88a0ca0c3e83",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_10",
//                        "value": "ab7448ad07e8361397213888d596462ea576683a5089e89e7f0f89d6287c9769",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_11",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_12",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_13",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_14",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_15",
//                        "value": "d8549ec3e68399eeef05fa44b1552ea4cd459bf6476e62716348651662bee73f",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_16",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_17",
//                        "value": "12ed2e819c021aae0f368d6100b6c100b6a1f36e33fc506132a26184834714bf",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_18",
//                        "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_19",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_20",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_21",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_22",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    },
//                    {
//                        "index": "pcr_23",
//                        "value": "0000000000000000000000000000000000000000000000000000000000000000",
//                        "pcr_bank": "SHA256"
//                    }
//                ],
//                "pcr_event_log_map": {
//                    "SHA1": [
//                        {
//                            "pcr_index": "pcr_17",
//                            "event_log": [
//                               {
//                                    "value": "69fba4144e24d63e9fa677b20dd781e84490f038",
//                                    "label": "HASH_START",
//                                    "info": {
//                                        "ComponentName": "HASH_START",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "45b0e0ccabd8160d0d019d80c5622cc5415c71a1",
//                                    "label": "BIOSAC_REG_DATA",
//                                    "info": {
//                                        "ComponentName": "BIOSAC_REG_DATA",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
//                                    "label": "CPU_SCRTM_STAT",
//                                    "info": {
//                                        "ComponentName": "CPU_SCRTM_STAT",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                    "label": "LCP_CONTROL_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_CONTROL_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                    "label": "LCP_DETAILS_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_DETAILS_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                    "label": "STM_HASH",
//                                    "info": {
//                                        "ComponentName": "STM_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                                    "label": "OSSINITDATA_CAP_HASH",
//                                    "info": {
//                                        "ComponentName": "OSSINITDATA_CAP_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e",
//                                    "label": "MLE_HASH",
//                                    "info": {
//                                        "ComponentName": "MLE_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                                    "label": "NV_INFO_HASH",
//                                    "info": {
//                                        "ComponentName": "NV_INFO_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                                    "label": "tb_policy",
//                                    "info": {
//                                        "ComponentName": "tb_policy",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "f3b26409294f95d0c60ea7c15ac260a2f3215e9d",
//                                    "label": "vmlinuz",
//                                    "info": {
//                                        "ComponentName": "vmlinuz",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "2ef8f9f592d7c61b7a9f6bca452060f89c013c7a",
//                                    "label": "initrd",
//                                    "info": {
//                                        "ComponentName": "initrd",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                }
//                            ],
//                            "pcr_bank": "SHA1"
//                        },
//                        {
//                            "pcr_index": "pcr_18",
//                            "event_log": [
//                               {
//                                    "value": "a395b723712b3711a89c2bb5295386c0db85fe44",
//                                    "label": "SINIT_PUBKEY_HASH",
//                                    "info": {
//                                        "ComponentName": "SINIT_PUBKEY_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
//                                    "label": "CPU_SCRTM_STAT",
//                                    "info": {
//                                        "ComponentName": "CPU_SCRTM_STAT",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                                    "label": "OSSINITDATA_CAP_HASH",
//                                    "info": {
//                                        "ComponentName": "OSSINITDATA_CAP_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                    "label": "LCP_CONTROL_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_CONTROL_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                                    "label": "LCP_AUTHORITIES_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_AUTHORITIES_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                                    "label": "NV_INFO_HASH",
//                                    "info": {
//                                        "ComponentName": "NV_INFO_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                               {
//                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                                    "label": "tb_policy",
//                                    "info": {
//                                        "ComponentName": "tb_policy",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                }
//                            ],
//                            "pcr_bank": "SHA1"
//                        }
//                    ],
//                    "SHA256": [
//                        {
//                            "pcr_index": "pcr_15",
//                            "event_log": [
//                                {
//                                    "value": "574d669fc8cae83fe53f32fbed23e581d78e0ab9307c8aa0ba1f5615f1194d43",
//                                    "label": "ISecL_Default_Application_Flavor_v2.2_TPM2.0-77a13c96-c04a-4d21-84f4-3b7c017d076d",
//                                    "info": {
//                                        "ComponentName": "ISecL_Default_Application_Flavor_v2.2_TPM2.0-77a13c96-c04a-4d21-84f4-3b7c017d076d",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "2dff3ae87e6dd29fb60c1c4b3bec614fbe5859eb84712318ecfbf41e7511e923",
//                                    "label": "ISecL_Default_Workload_Flavor_v2.2-eb01c331-57aa-48cd-95db-87c16f1d1102",
//                                    "info": {
//                                        "ComponentName": "ISecL_Default_Workload_Flavor_v2.2-eb01c331-57aa-48cd-95db-87c16f1d1102",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                }
//                            ],
//                            "pcr_bank": "SHA256"
//                        },
//                        {
//                            "pcr_index": "pcr_17",
//                            "event_log": [
//                                {
//                                    "value": "940a487b3a2b3a82858b18c20f55ad9c73522f43aab071f62350093bd7c2d6ba",
//                                    "label": "HASH_START",
//                                    "info": {
//                                        "ComponentName": "HASH_START",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "7980d1a2034e18a33da6fde28ddd8a296c7147a3e4cea6dc32997f4fc40a97a5",
//                                    "label": "BIOSAC_REG_DATA",
//                                    "info": {
//                                        "ComponentName": "BIOSAC_REG_DATA",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                                    "label": "CPU_SCRTM_STAT",
//                                    "info": {
//                                        "ComponentName": "CPU_SCRTM_STAT",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                    "label": "LCP_CONTROL_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_CONTROL_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                    "label": "LCP_DETAILS_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_DETAILS_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                    "label": "STM_HASH",
//                                    "info": {
//                                        "ComponentName": "STM_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                                    "label": "OSSINITDATA_CAP_HASH",
//                                    "info": {
//                                        "ComponentName": "OSSINITDATA_CAP_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186",
//                                    "label": "MLE_HASH",
//                                    "info": {
//                                        "ComponentName": "MLE_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                                    "label": "NV_INFO_HASH",
//                                    "info": {
//                                        "ComponentName": "NV_INFO_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                                    "label": "tb_policy",
//                                    "info": {
//                                        "ComponentName": "tb_policy",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "7b533984a9a209e70c1770205df45c7ca671cf2f90e0a83737949324e3ec1778",
//                                    "label": "vmlinuz",
//                                    "info": {
//                                        "ComponentName": "vmlinuz",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "2b6b6bcd39f809e87b14a8a47e751a6919c4ee57b46319f29fa35379c8d84f7a",
//                                    "label": "initrd",
//                                    "info": {
//                                        "ComponentName": "initrd",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                }
//                            ],
//                            "pcr_bank": "SHA256"
//                        },
//                        {
//                            "pcr_index": "pcr_18",
//                            "event_log": [
//                                {
//                                    "value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
//                                    "label": "SINIT_PUBKEY_HASH",
//                                    "info": {
//                                        "ComponentName": "SINIT_PUBKEY_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                                    "label": "CPU_SCRTM_STAT",
//                                    "info": {
//                                        "ComponentName": "CPU_SCRTM_STAT",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                                    "label": "OSSINITDATA_CAP_HASH",
//                                    "info": {
//                                        "ComponentName": "OSSINITDATA_CAP_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                    "label": "LCP_CONTROL_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_CONTROL_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                                    "label": "LCP_AUTHORITIES_HASH",
//                                    "info": {
//                                        "ComponentName": "LCP_AUTHORITIES_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                                    "label": "NV_INFO_HASH",
//                                    "info": {
//                                        "ComponentName": "NV_INFO_HASH",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                },
//                                {
//                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                                    "label": "tb_policy",
//                                    "info": {
//                                        "ComponentName": "tb_policy",
//                                        "EventName": "OpenSource.EventName"
//                                    }
//                                }
//                            ],
//                            "pcr_bank": "SHA256"
//                        }
//                    ]
//                }
//            },
//            "binding_key_certificate": "MIIFHDCCA4SgAwIBAgIRA/K2fjaHwJVEX8DlX0VdW9EwDQYJKoZIhvcNAQEMBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjAwNzE5MTcxMjEzWhcNMzAwNzE5MTcxMjEzWjAiMSAwHgYDVQQDDBdCaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASEwDQYJKoZIhvcNAQEBBQADggEOADCCAQkCggEBAJnSZHhEg4fqk3OU+H59y3DiWEg1hWySu/qgnpnUWZKrzWPLvyQdeBBRO6hIT43bdhXWhfiu1AOgduBOGcUmBqLM9RvX1+HhUWZ2FcfsH/prs6hxWRDa6BRvxPYmFZoietT2JtrBn8kq6Smeflo3VHIef52qFWLoGVrv+5V79yZmjMfcCq4HMvklR2ELiUVfDCfJdAnxp5tQak+NOfzQhiHbjPV/5SKFvS60e1qMX+7DaIMzeHuBZLKU4kytGFEHkcPkdwvALpQsNhnnc0zLFRyeAZVXcJYc4fE7MGkIm2yyGpW0izDDQnlCghKaLxsh/CoKzrB1+zyxDeGQDRfPbC0CAgEAo4IBzDCCAcgwDgYDVR0PAQH/BAQDAgWgMIGdBgdVBIEFAwIpBIGR/1RDR4AXACIACx6Zgv7MibJQ6gE53QmMHmHU9u5uKGObJwgIhFLqahZZAAQA/1WqAAAAANpTgn8AAAAJAAAAAQEABwAoAAgyAAAiAAvML2xwknp3hNsQ8Fa4xiVp+Gm/3FrOrl5nM927N2TimAAiAAs70Q4QKWR445dxMBYOHECnHeh+vsYYBOJKj9XhBfE8yDCCARQGCFUEgQUDAikBBIIBBgAUAAsBAGBXD+UihZDF3CgMRNtI03JPtsfQz8j4ErnyazO3qHSbHlIKwG2PG3lX8mZhzOSXN3TTa9nyqGd1KCdR5QPwW+AzzWRWKvq36X3bW1otxqI2VSbnkMBzEgt4jZStwPoPeztpyaityB/UZ4wmiGtLAvbnEEJBtpVa7Je6tlPOjQfP31izthGkJZfsC0s6U+FT5aPu6HVPQqmmgLJgreUStqidEAxJo16Skg5Ft3RoVcOYq6PIOb/6h74exbrhb6OhwwkbJA3ysaukYvTZid1zaHx+RhyZ5bElEISLi6ey1zVKZn+xOxwJ810ELo3MeolGDVGGIartkMboEJ2gQHwmBAwwDQYJKoZIhvcNAQEMBQADggGBAJ3hp8wW4cp9dwpnV8kEIbpOm48HvuFYy8j9LmcHGQZQcis2cAQnZycG00qmtCNPUqGhhk8+cFNoE4F67IdTKPDITsBdEwp0SEuYWqK0P4XkK1o+KfHWzyscJSErgX6nQMMvDwKOTqKmgRRRUj4povd+1Ov/LpH73Lh1gyJLtzADFBsF1t+gFk+l2jH8q/Pix10DS+VJtY6PLwGCJbuMmVzo8Qlh7SpJ+olB4T3jIyiMNB2RgJTNcUiWzAOtb35YVuXdpcr+9Yptaz/HEQTDW1HOfI7VwGGbfFdcGIK2ArvdprI2gyBZcGc9WVkOrciyXcrEP5La87AClWAM0Irv93oxSnAU6mmorsaWyooxf4dUbv3RXGTou8CENEFdg8g+REQ2wZEsYiBwzyFXZPEe0QbZbfVuveHhuYiJ2YW3EQ2SdRhI/4yprry/IdCB5SIkWzktrzMX4CnC4q72FXEMUsfFFNcreg2Tj1sH94uhOnhQubUtaaswCxFHpazbuS9V9Q==",
//            "measurement_xmls": [
//                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Application_Flavor_v2.2_TPM2.0\" Uuid=\"77a13c96-c04a-4d21-84f4-3b7c017d076d\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/bin\">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/dracut_files\">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/initrd_hooks\">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/lib\">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/mkinitrd_files\">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir><File Path=\"/opt/tbootxm/bin/tpmextend\">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File><File Path=\"/opt/tbootxm/bin/measure\">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File><File Path=\"/opt/tbootxm/bin/configure_host.sh\">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File><File Path=\"/opt/tbootxm/bin/generate_initrd.sh\">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File><File Path=\"/opt/tbootxm/bin/measure_host\">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File><File Path=\"/opt/tbootxm/bin/tboot-xm-uninstall.sh\">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File><File Path=\"/opt/tbootxm/bin/functions.sh\">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File><File Path=\"/opt/tbootxm/dracut_files/check\">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File><File Path=\"/opt/tbootxm/dracut_files/install\">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File><File Path=\"/opt/tbootxm/dracut_files/module-setup.sh\">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File><File Path=\"/opt/tbootxm/initrd_hooks/tcb\">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File><File Path=\"/opt/tbootxm/lib/libwml.so\">4b33910d5d03045275c2e8593f8bebefc2d4689c575a198a516121b25f44269107fb5075d1b5d9b35cf0b1da56b9e1e9</File><File Path=\"/opt/tbootxm/lib/create_menuentry.pl\">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File><File Path=\"/opt/tbootxm/lib/update_menuentry.pl\">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File><File Path=\"/opt/tbootxm/lib/remove_menuentry.pl\">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File><File Path=\"/opt/tbootxm/mkinitrd_files/setup-measure_host.sh\">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><File Path=\"/opt/trustagent/bin/tagent\">49d1b74611cfe29f39e917bfe2f2682105144cbbc0779de07c33486d868ef24a475d61e5b48a6a91e3bf3943b6827706</File><File Path=\"/opt/trustagent/bin/module_analysis.sh\">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File><File Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><File Path=\"/opt/trustagent/bin/module_analysis_da_tcg.sh\">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File><CumulativeHash>5dd16d5e60b2d211ce1b416e0d9042d91b0e79d59ea24ec19d387778f44d643fd39160c4d9537590a81bf3de424c524b</CumulativeHash></Measurement>",
//                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Workload_Flavor_v2.2\" Uuid=\"eb01c331-57aa-48cd-95db-87c16f1d1102\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/workload-agent/bin\">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir><File Path=\"/opt/workload-agent/bin/wlagent\">ad913d6e02f1055694dad2b3a1e81ec9c783d4b3f473d66ace78cdc83be4df7cf885a0545c1e44c8badbe5f3692ff04f</File><CumulativeHash>45d785cd9bccc298ea0c4ce416f604b6982396ce3182bfdf2d835285dc21e0439187405407d258711c2fdae9ed6ecc98</CumulativeHash></Measurement>"
//            ]
//        }
//    }
//  ---
