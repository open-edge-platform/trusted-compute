/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// Report response payload
// swagger:parameters Report
type Report struct {
	// in:body
	Body hvs.Report
}

// ReportCollection response payload
// swagger:parameters ReportCollection
type ReportCollection struct {
	// in:body
	Body hvs.ReportCollection
}

// Report request payload
// swagger:parameters ReportCreateRequest
type ReportCreateRequest struct {
	// in:body
	Body hvs.ReportCreateRequest
}

// ---

// swagger:operation GET /reports Reports Search-Reports
// ---
//
// description: |
//   A report contains the trust information produced by the flavor verification process. It provides details on if the host is trusted and the flavors it matched, or came closest to matching.
//   If the host is untrusted, the report will include faults which describe why the host is untrusted. These faults allow for easy analysis and remediation of an untrusted
//   result.
//
//   A report can be returned in JSON format, or it can be returned in SAML format. A SAML report is provided in XML format and contains the same trust information in a specific attribute format.
//   A SAML report also includes a signature that can be verified by the Host Verification Service’s SAML public key.
//
//   Reports have a configurable validity period with default period of 24 hours or 86400 seconds. The Host Verification service has a background refresh process that queries for reports where the expiration time is within the next 5 minutes, and triggers generation of a new report for all results.
//   This is checked every 2 minutes by default, and can be configured by changing property in the configuration. In this way fresh reports are generated before older reports expire.
//
//   <b>Searches for reports</b>
//
// x-permissions: reports:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Report ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: limit
//   description: Limit of the number of items in a page.
//   in: query
//   type: integer
//   required: false
//   default: 1000
// - name: afterId
//   description: Lext row id after which db must be queried
//   in: query
//   type: integer
//   required: false
// - name: hostId
//   description: host Id of the host. If this parameter is specified, it will return report only for active host with specified host id.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: hostName
//   description: Hostname of the host. If this parameter is specified, it will return report only for active host with specified host name.
//   in: query
//   type: string
//   required: false
// - name: hostHardwareId
//   description: Hardware UUID of the host. If this parameter is specified, it will return report only for active host with specified host hardware uuid.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: hostStatus
//   description: Current state of an active host.  A list of host states is defined in the description section of the HostStatus.
//   in: query
//   type: string
//   format: string
//   required: false
// - name: numberOfDays
//   description: |
//      Results returned will be restricted to between the current date and number of days prior. This option will override other date options.
//      min: 0
//      max: 365
//   in: query
//   type: integer
//   required: false
// - name: fromDate
//   description: |
//     Results returned will be restricted to after this date. Currently the following ISO 8601 date formats are supported for date parameters
//         date                                   Ex: fromDate=2006-01-02
//         date+time                              Ex: fromDate=2006-01-02 15:04:05
//         date+time(with milli seconds)          Ex: fromDate=2006-01-02T15:04:05.000Z
//         date+time(with micro seconds)          Ex: fromDate=2006-01-02T15:04:05.000000Z
//   in: query
//   type: string
//   format: date-time
//   required: false
// - name: toDate
//   description: |
//     Results returned will be restricted to before this date. Currently the following ISO 8601 date formats are supported for date parameters
//         date                                   Ex: toDate=2006-01-02
//         date+time                              Ex: toDate=2006-01-02 15:04:05
//         date+time(with milli seconds)          Ex: toDate=2006-01-02T15:04:05.000Z
//         date+time(with micro seconds)          Ex: toDate=2006-01-02T15:04:05.000000Z
//   in: query
//   type: string
//   format: date-time
//   required: false
// - name: latestPerHost
//   description:  Returns only the latest report for each host. If latestPerHost is specified in conjuction with a date filter, it will return the latest report for within the specified date range per host.
//   in: query
//   type: boolean
//   required: false
//   default: true
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the reports.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/ReportCollection"
//   '400':
//     description: Invalid search criteria provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/reports?numberOfDays=2&amp;latestPerHost=false
// x-sample-call-output: |
//     {
//         "id": "8a545a4f-d282-4d91-8ec5-bcbe439dcfbc",
//         "host_id": "94824cb6-d6c8-4faf-83b0-125996ceebe2",
//         "trust_information": {
//                 "flavors_trust": {
//                             "HOST_UNIQUE":
//                                 {
//                                   "trust": true,
//                                    "rules":
//                                        [
//                                         {
//                                             "rule":
//                                                 {
//                                             "rule_name": "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIncludes",
//                                             "markers":
//                                                 [
//                                                   "HOST_UNIQUE"
//                                                 ],
//                                             "pcr_bank": "SHA256",
//                                             "pcr_index": "pcr_18",
//                                             "expected":
//                                              [
//                                                 {
//                                             "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                             "label": "LCP_CONTROL_HASH",
//                                             "info":
//                                                {
//                                                  "ComponentName": "LCP_CONTROL_HASH",
//                                                  "EventName": "OpenSource.EventName"
//                                                 }
//                                                }
//                                             ],
//                                           },
//                                     "flavor_id": "a774ddad-fca1-4670-86b2-605c88a16dab",
//                                     "trusted": true
//                                        },
//                                      ]
//                              },
//                             "OS": {
//                                             "trust": true,
//                                             "rules": [...]
//                                   },
//
//                             "PLATFORM": {       "trust": true,
//                                             "rules": [...]
//                                     },
//                             },
//                             "SOFTWARE": {       "trust": true,
//                                             "rules": [...]
//                                     },
//                             },
//         "OVERALL": true,
//         "created": "2018-07-23T16:39:52-0700",
//         "expiration": "2018-07-23T17:39:52-0700"
//     }

// ---

// swagger:operation POST /reports Reports Create-Report
// ---
//
// description: |
//   Creates a Report.
//
//   The serialized ReportCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | host_id                        | ID of host |
//    | host_name                      | hostname of host |
//    | hardware_uuid                  | Hardware UUID of host |
//
//
// x-permissions: reports:create
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/ReportCreateRequest"
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
// - name: process
//   description: Create the report asynchronously by adding the host to flavor-verification queue
//   type: string
//   in: query
//   enum:
//     - async
// responses:
//   '201':
//     description: Successfully created the report.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Report"
//   '400':
//     description: Invalid search criteria provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/reports
// x-sample-call-input: |
//     {
//         "host_name":"host-1"
//     }
// x-sample-call-output: |
//     {
//           "id": "8a545a4f-d282-4d91-8ec5-bcbe439dcfbc",
//           "host_id": "94824cb6-d6c8-4faf-83b0-125996ceebe2",
//           "trust_information": {
//                   "flavors_trust": {
//                               "HOST_UNIQUE":
//                                   {
//                                     "trust": true,
//                                      "rules":
//                                          [
//                                           {
//                                               "rule":
//                                                   {
//                                               "rule_name": "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIncludes",
//                                               "markers":
//                                                   [
//                                                     "HOST_UNIQUE"
//                                                   ],
//                                               "pcr_bank": "SHA256",
//                                               "pcr_index": "pcr_18",
//                                               "expected":
//                                                [
//                                                   {
//                                               "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                               "label": "LCP_CONTROL_HASH",
//                                               "info":
//                                                  {
//                                                    "ComponentName": "LCP_CONTROL_HASH",
//                                                    "EventName": "OpenSource.EventName"
//                                                   }
//                                                  }
//                                               ],
//                                             },
//                                       "flavor_id": "a774ddad-fca1-4670-86b2-605c88a16dab",
//                                       "trusted": true
//                                          },
//                                        ]
//                                },
//                               "OS": {
//                                               "trust": true,
//                                               "rules": [...]
//                                     },
//
//                               "PLATFORM": {       "trust": true,
//                                               "rules": [...]
//                                       },
//
//                               "SOFTWARE": {       "trust": true,
//                                               "rules": [...]
//                                       }
//                               }
//                           },
//                   "OVERALL": true,
//           "created": "2018-07-23T16:39:52-0700",
//           "expiration": "2018-07-23T17:39:52-0700"
//     }

// ---

// swagger:operation GET /reports/{report_id} Reports Retrieve-Report
// ---
//
// description: |
//   Retrieves a report.
//   Returns - The serialized Report Go struct object that was retrieved.
// x-permissions: reports:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: report_id
//   description: Unique ID of the Report.
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
//     description: Successfully retrieved the Report.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Report"
//   '404':
//     description: No relevant report record found.
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error.
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/reports/8a545a4f-d282-4d91-8ec5-bcbe439dcfbc
// x-sample-call-output: |
//   {
//     "id": "8a545a4f-d282-4d91-8ec5-bcbe439dcfbc",
//     "host_id": "94824cb6-d6c8-4faf-83b0-125996ceebe2",
//     "trust_information": {
//       "flavors_trust": {
//         "HOST_UNIQUE": {
//           "trust": true,
//           "rules": [
//             {
//               "rule": {
//                 "rule_name": "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIncludes",
//                 "markers": [
//                   "HOST_UNIQUE"
//                 ],
//                 "pcr_bank": "SHA256",
//                 "pcr_index": "pcr_18",
//                 "expected": [
//                   {
//                     "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                     "label": "LCP_CONTROL_HASH",
//                     "info": {
//                       "ComponentName": "LCP_CONTROL_HASH",
//                       "EventName": "OpenSource.EventName"
//                     }
//                   }
//                 ]
//               },
//               "flavor_id": "a774ddad-fca1-4670-86b2-605c88a16dab",
//               "trusted": true
//             }
//           ]
//         },
//         "OS": {
//           "trust": true,
//           "rules": [
//             ...
//           ]
//         },
//         "PLATFORM": {
//           "trust": true,
//           "rules": [
//             ...
//           ]
//         },
//         "SOFTWARE": {
//           "trust": true,
//           "rules": [
//             ...
//           ]
//         }
//       },
//       "OVERALL": true,
//       "created": "2018-07-23T16:39:52-0700",
//       "expiration": "2018-07-23T17:39:52-0700"
//     }
//   }
