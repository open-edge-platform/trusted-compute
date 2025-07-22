/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// FlavorTemplate response payload
// swagger:parameters FlavorTemplate
type FlavorTemplate struct {
	// in: body
	Body hvs.FlavorTemplate
}

// FlavorTemplateReq request payload
// swagger:parameters FlavorTemplateReq
type FlavorTemplateReq struct {
	// in: body
	Body hvs.FlavorTemplateReq
}

// FlavorTemplateFlavorgroup response payload
// swagger:parameters FlavorTemplateFlavorgroup
type FlavorTemplateFlavorgroup struct {
	// in: body
	Body hvs.FlavorTemplateFlavorgroup
}

// FlavorTemplateFlavorgroupCreateRequest request payload
// swagger:parameters FlavorTemplateFlavorgroupCreateRequest
type FlavorTemplateFlavorgroupCreateRequest struct {
	// in: body
	Body hvs.FlavorTemplateFlavorgroupCreateRequest
}

// FlavorTemplateFlavorgroupCollection response payload
// swagger:parameters FlavorTemplateFlavorgroupCollection
type FlavorTemplateFlavorgroupCollection struct {
	// in: body
	Body hvs.FlavorTemplateFlavorgroupCollection
}

// ---

// swagger:operation GET /flavor-templates/{flavortemplate_id} Flavortemplates Retrieve-FlavorTemplate
// ---
//
// description: |
//   Retrieves a flavor template.
//
// x-permissions: flavor-template:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavortemplate
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
//     description: Successfully retrieved the flavortemplate
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplate"
//   '400':
//     description: Invalid or Bad request
//   '401':
//     description: Unauthorized request
//   '404':
//     description: Flavortemplate record not found
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/d6f81340-b033-4fae-8ccf-795430f486e7
// x-sample-call-output: |
//   {
//       "id": "d6f81340-b033-4fae-8ccf-795430f486e7",
//       "label": "default_uefi",
//       "condition": [
//           "//meta/vendor='Linux'",
//           "//meta/tpm_version/='2.0'",
//           "//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
//       ],
//       "flavor-parts": {
//           "PLATFORM": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 0,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": true
//                   }
//               ]
//           },
//           "OS": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 7,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": null,
//                       "eventlog_includes": [
//                           "shim",
//                           "db",
//                           "kek",
//                           "vmlinuz"
//                       ]
//                   }
//               ]
//           }
//       }
//   }

// ---

// swagger:operation POST /flavor-templates Flavortemplates Create-FlavorTemplate
// ---
// description: |
//
//   Flavor Template: Flavor templates are used to implement dynamic flavor generation. It supports definition of rules for Linux hosts. The templates need to be defined in JSON format. The rules defined will be used for matching the templates while generating flavors.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | flavor_template                | Skeleton to generate dynamic flavors  |
//    | flavorgroup_names              | (Optional) Flavor group names that the created flavor-template(s) will be associated with. If not provided, created flavor-template will be associated with automatic flavor group. |
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | ID                             | Unique ID of flavor template. |
//    | Label                          | Name of the flavortemplate to be created. |
//    | Condition                      | The “condition” uses meta-data from the host-manifest to determine if the flavor-template should be applied. An array of 'jsonquery' statements that are used to determine if the template should be executed. For example, “if TBOOT is installed”, use the information in the child “flavor-parts” to copy event-logs from the manifest’s PCR 17 & 18 to the PLATFORM flavor-part. |
//    | FlavorParts                    | One or more flavor-part entities that are generated by the template. |
//
//   FlavorParts: The type or classification of the flavor. For more information on flavor parts, see the
//   product guide.
//   Supported FlavorParts types are, PLATFORM, OS and HOST_UNIQUE
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | Meta                           | Provides the template-author the option to populate arbitrary key/value pairs that will be copied to flavor-part’s “meta/description” entity. |
//    | PcrRules                       | Instructs the flavor creation engine to copy PCR bank values from the host-manifest to the resulting flavor-part. |
//
//   PcrRules: An array of verification rules that will be applied to a PCR.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | PCR                            | Lists the rules that are to be applied to each PCR.  There cannot be duplicate index/banks in this array. |
//    | PcrMatches                     | Setting ‘pcr_matches’ to true in the flavor-template will update the flavor-part to enforce “PCR Matches Constants” rules during flavor verfication. |
//    | EventLogEquals                 | Event log equals contains “eventlog_equals” section will update the flavor-part to enforce “PCR Event Log Equals” rules during verification.  The optional “excluding_tags” element can be used to omit events with a one or more “tags” during verification. |
//    | EventLogIncludes               | EventLogInclude contains “eventlog_includes” section will update the flavor-part to enforce “PCR Event Log Includes” rules during verification. |
//
//   Creates a Flavor template and stores it in the database.
//
// x-permissions: flavor-template:create
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
//    "$ref": "#/definitions/FlavorTemplateReq"
// - name: Content-Type
//   description: Content-Type header
//   required: true
//   in: header
//   type: string
// - name: Accept
//   description: Accept header
//   required: true
//   in: header
//   type: string
// responses:
//   '200':
//     description: Successfully created the flavortemplate.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplate"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates
// x-sample-call-input: |
//    {
//    flavor_template : {
//       "label": "default-uefi",
//       "condition": [
//           "//host_info/os_name//*[text()='RedHatEnterprise']",
//           "//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
//           "//host_info/hardware_features/UEFI/enabled//*[text()='true'] or //host_info/hardware_features/UEFI/meta/secure_boot_enabled//*[text()='true']"
//       ],
//       "flavor_parts": {
//           "PLATFORM": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 0,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": true,
//                       "eventlog_equals": {}
//                   }
//               ]
//           },
//           "OS": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 7,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": true,
//                       "eventlog_includes": [
//                           "shim",
//                           "db",
//                           "kek",
//                           "vmlinuz"
//                       ]
//                   }
//               ]
//           }
//       }
//    }
//    }
//
// x-sample-call-output: |
//    {
//        "id": "3f8a57a8-f6d7-49ea-8309-0e00b997fbce",
//         "label": "default-uefi",
//         "condition": [
//             "//host_info/os_name//*[text()='RedHatEnterprise']",
//             "//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
//             "//host_info/hardware_features/UEFI/enabled//*[text()='true'] or //host_info/hardware_features/UEFI/meta/secure_boot_enabled//*[text()='true']"
//         ],
//         "flavor_parts": {
//             "PLATFORM": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 0,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": true,
//                         "eventlog_equals": {}
//                     }
//                 ]
//             },
//             "OS": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": true,
//                         "eventlog_includes": [
//                             "shim",
//                             "db",
//                             "kek",
//                             "vmlinuz"
//                         ]
//                     }
//                 ]
//             }
//         }
//     }

// ---

// swagger:operation GET /flavor-templates Flavortemplates Search-FlavorTemplates
// ---
//
// description: |
//   Retrieves all the flavor templates available in the database.
//
// x-permissions: flavor-template:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: includeDeleted
//   description: Boolean value to indicate whether the deleted templates should be included in the search.
//   in: query
//   required: false
//   type: string
//   format: bool
// - name: id
//   description: Flavor template which has given uuid value will be returned
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: label
//   description: Flavor templates that have given label will be included
//   in: query
//   type: string
//   required: false
// - name: conditionContains
//   description: Flavor templates that contain the given condition will be included
//   in: query
//   type: string
//   required: false
// - name: flavorPartContains
//   description: Flavor templates that contain the specified flavor part will be included
//   in: query
//   type: string
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
//     description: Successfully retrieved the flavortemplate
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplate"
//   '400':
//     description: Invalid or Bad request
//   '401':
//     description: Unauthorized request
//   '404':
//     description: Flavortemplate record not found
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates
// x-sample-call-output: |
//   [
//     {
//         "id": "d6f81340-b033-4fae-8ccf-795430f486e7",
//         "label": "default_uefi",
//         "condition": [
//             "//meta/vendor='Linux'",
//             "//meta/tpm_version/='2.0'",
//             "//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
//         ],
//         "flavor-parts": {
//             "PLATFORM": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 0,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": true
//                     }
//                 ]
//             },
//             "OS": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": null,
//                         "eventlog_includes": [
//                             "shim",
//                             "db",
//                             "kek",
//                             "vmlinuz"
//                         ]
//                     }
//                 ]
//             }
//         }
//     },
//     {
//         "id": "3f8a57a8-f6d7-49ea-8309-0e00b997fbce",
//         "label": "default-pfr",
//         "condition": [
//           "//meta/vendor='Linux'",
//           "//meta/tpm_version/='2.0'"
//         ],
//         "flavor-parts": {
//             "PLATFORM": {
//                 "meta": {
//                     "vendor":"Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "eventlog_includes": ["Inte PFR"]
//                     }
//                 ]
//             }
//         }
//     }
//   ]

// ---

// swagger:operation DELETE /flavor-templates/{flavortemplate_id} Flavortemplates Delete-FlavorTemplate
// ---
//
// description: |
//   Deletes a flavor template from database.
// x-permissions: flavor-template:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavortemplate
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully performed lazy delete on flavor template based on flavortemplate_id
//   '400':
//     description: Invalid or Bad request
//   '401':
//     description: Unauthorized request
//   '404':
//     description: Flavortemplate record not found
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/d6f81340-b033-4fae-8ccf-795430f486e7

// ---
// swagger:operation POST /flavor-templates/{flavortemplate_id}/flavorgroups  Flavortemplates  Create-FlavorgroupLink
// ---
//
// description: |
//   Creates an association between a FlavorTemplate and FlavorGroup record.
//
//   The serialized FlavorTemplateFlavorgroupCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute                      | Description                                                       |
//    |--------------------------------|-------------------------------------------------------------------|
//    | flavorgroup_id                 | ID of the Flavorgroup record to be linked with the FlavorTemplate |
//
//
//
// x-permissions: flavor-template:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: flavortemplate_id
//   required: true
//   in: path
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/FlavorTemplateFlavorgroupCreateRequest"
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
//     description: Successfully linked the FlavorTemplate and FlavorGroup.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplateFlavorgroupCreateRequest"
//   '400':
//     description: Invalid request body provided/FlavorgroupID provided in request body does not exist/FlavorTemplate-FlavorGroup link already exists
//   '404':
//     description: FlavorTemplate ID in request path does not exist
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/8d7964db-4e4d-49a0-b441-1beabbcebf78/flavorgroups
// x-sample-call-input: |
//    {
//        "flavorgroup_id":"1429cebf-1c09-4e78-b2aa-da10e58d7446",
//    }
// x-sample-call-output: |
//   {
//     "flavortemplate_id": "8d7964db-4e4d-49a0-b441-1beabbcebf78",
//     "flavorgroup_id": "1429cebf-1c09-4e78-b2aa-da10e58d7446"
//   }

// ---

// swagger:operation GET /flavor-templates/{flavortemplate_id}/flavorgroups/{flavorgroup_id}  Flavor-templates Retrieve-Flavorgrouplink
// ---
//
// description: |
//   Retrieves a FlavorTemplate-FlavorGroup association.
//   Returns - The FlavorTemplateFlavorGroupLink in JSON format that represents the association.
// x-permissions: flavor-template:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavor template.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
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
//     description: Successfully retrieved the FlavorTemplate Flavorgroup link.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplateFlavorgroup"
//   '404':
//     description: Flavortemplate/Flavorgroup record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/8d7964db-4e4d-49a0-b441-1beabbcebf78/flavorgroups/1429cebf-1c09-4e78-b2aa-da10e58d7446
// x-sample-call-output: |
//  {
//    "flavortemplate_id": "8d7964db-4e4d-49a0-b441-1beabbcebf78",
//    "flavorgroup_id": "1429cebf-1c09-4e78-b2aa-da10e58d7446"
//  }

// ---

// swagger:operation DELETE /flavor-templates/{flavortemplate_id}/flavorgroups/{flavorgroup_id}  Flavortemplates  Delete-FlavorgroupLink
// ---
//
// description: |
//   Deletes an individual Flavortemplate Flavorgroup link.
// x-permissions: flavor-template:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavor template.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the Flavortemplate-Flavorgroup link.
//   '404':
//     description: Flavortemplate/Flavorgroup record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/826501bd-3c75-4839-a08f-db5f744f8498/flavorgroups/e5574593-0f92-41f0-8f2d-93b97cea9c06
// ---

// swagger:operation GET /flavor-templates/{flavortemplate_id}/flavorgroups Flavortemplates Search-Flavorgrouplinks
// ---
//
// description: |
//   Retrieves a list of FlavorTemplate-FlavorGroup associations corresponding to a flavor template.
//   Returns - The FlavorTemplateFlavorgroupCollection in JSON format that are associated with the flavor template.
// x-permissions: flavor-template:search
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavor template.
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
//     description: Successfully retrieved the FlavorTemplateFlavorgroupCollection.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplateFlavorgroupCollection"
//   '404':
//     description: Flavor Template record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/e5574593-0f92-41f0-8f2d-93b97cea9c06/flavorgroups
// x-sample-call-output: |
//  {
//    "flavorgroup_flavortemplate_links": [
//    {
//      "flavortemplate_id": "e5574593-0f92-41f0-8f2d-93b97cea9c06",
//      "flavorgroup_id": "fdd4240b-2369-4175-80e7-7fbf8ec78ce8"
//    },
//    {
//      "flavortemplate_id": "e5574593-0f92-41f0-8f2d-93b97cea9c06",
//      "flavorgroup_id": "bf8a9882-8a49-43ca-8052-b666bd7c0172"
//    }
//    ]
//  }
