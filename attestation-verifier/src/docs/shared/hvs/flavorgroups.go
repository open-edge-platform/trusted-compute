/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// FlavorGroup response payload
// swagger:parameters FlavorGroup
type FlavorGroup struct {
	// in:body
	Body hvs.FlavorGroup
}

// FlavorgroupCollection response payload
// swagger:parameters FlavorgroupCollection
type FlavorgroupCollection struct {
	// in:body
	Body hvs.FlavorgroupCollection
}

// FlavorgroupFlavorLinkCriteria request payload for creating FlavorGroup-Flavor links
// swagger:parameters FlavorgroupFlavorLinkCriteria
type FlavorgroupFlavorLinkCriteria struct {
	// in:body
	Body hvs.FlavorgroupFlavorLinkCriteria
}

// FlavorgroupFlavorLink response payload for RetrieveFlavor
// swagger:parameters FlavorgroupFlavorLink
type FlavorgroupFlavorLink struct {
	// in:body
	Body hvs.FlavorgroupFlavorLink
}

// FlavorgroupFlavorLinkCollection response payload for SearchFlavors
// swagger:parameters FlavorgroupFlavorLinkCollection
type FlavorgroupFlavorLinkCollection struct {
	// in:body
	Body hvs.FlavorgroupFlavorLinkCollection
}

// ---
//
// swagger:operation GET /flavorgroups Flavorgroups Search
// ---
//
// description: |
//
//   <b>Flavor Group</b>: A flavor group represents a collection of flavors that has a specified policy, which is used
//   to verify host against those flavors. Flavors can be added to a flavor group, and hosts can be associated with a
//   flavor group.
//
//   The flavor group policy lists the individual flavor parts and the match policy rules associated with each one.
//
//   <b>Flavor Part</b>: The type or classification of the flavor. For more information on flavor parts, see the
//   product guide.
//       - PLATFORM
//       - OS
//       - ASSET_TAG
//       - HOST_UNIQUE
//       - SOFTWARE
//
//   <b>Match Policy</b>: The policy which defines how the host is verified against the flavors in the flavor group for
//   the specified flavor part.
//
//     <u>Match Type</u>: An enum whose value identifies how the policy is evaluated for the specified flavor part.
//
//      | Match Type | Description |
//      |------------|-------------|
//      |  ANY_OF    | The host can match any of the flavors of this type (flavor part) in the flavor group, but it <br> must match at least one. |
//      |  ALL_OF    | The host must match each and every one of the flavors of this type (flavor part) in <br> the flavor group. |
//      |  LATEST    | The host must match latest of the flavors of this type (flavor part) in the flavor group. |
//
//
//     <u>Required</u>: An enum whose value determines whether the flavor part needs to be evaluated.
//
//      | Required            | Description |
//      |---------------------|-------------|
//      | REQUIRED            | A flavor of this type (flavor part) must exist in the flavor group in order for the <br> host to be trusted. |
//      | REQUIRED_IF_DEFINED | If a flavor of this type(flavor part) exists in the flavorgroup, then the corresponding <br> flavor is required/mandatory. If the flavor of this type is not present in the flavorgroup,<br> then flavor part will be ignored and host will still be trusted |
//
//
//   <b>Default Flavor Groups</b>: Four flavor groups exist by default.
//
//      | Flavorgroup         | Description |
//      |---------------------|-------------|
//      |  automatic          | Default flavor group for flavor verification. |
//      |  host_unique        | Default flavor group for host unique flavor parts. All host unique flavor parts are <br> associated with this flavor group regardless of user settings. This flavor group’s <br> policy is null, and the match policy for its flavor parts are defined in each <br> individual separate flavor group. This separation is required for backend processing <br> and handling of the host unique flavors. Host Unique Flavor Parts: ASSET_TAG, HOST_UNIQUE |
//      |  platform_software  | Default flavor group for default platform software flavors for application integrity <br> of Trust Agent |
//      |  workload_software  | Default flavor group for default platform software flavors for application integrity <br> of Workload Agent |
//
//   <b>Searches for flavor groups</b>
//   Only one identifying parameter can be specified to search flavorgroups which will return flavorgroup collection as
//   a result.
//
// x-permissions: flavorgroups:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Flavor group ID
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
//   description: Next row id after which db must be queried
//   in: query
//   type: integer
//   required: false
// - name: nameEqualTo
//   description: Flavor group name.
//   in: query
//   type: string
//   required: false
// - name: nameContains
//   description: Substring of flavor group name.
//   in: query
//   type: string
//   required: false
// - name: includeFlavorContent
//   description: Boolean value to indicate whether the content of the flavors contained within the <br> specified flavor group should be included in the response body. Default value is false.
//   in: query
//   type: boolean
//   required: false
// - name: Accept
//   required: true
//   in: header
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the flavorgroups.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorgroupCollection"
//   '400':
//     description: Invalid values for search parameters
//   '415':
//     description: Invalid Accept Header in Request
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups
// x-sample-call-output: |
//    {
//        "flavorgroups": [
//            {
//                "id": "826501bd-3c75-4839-a08f-db5f744f8498",
//                "name": "automatic",
//                "flavor_match_policy_collection": {
//                    "flavor_match_policies": [
//                        {
//                            "flavor_part": "PLATFORM",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED"
//                            }
//                        },
//                        {
//                            "flavor_part": "OS",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED"
//                            }
//                        },
//                        {
//                            "flavor_part": "ASSET_TAG",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED_IF_DEFINED"
//                            }
//                        },
//                        {
//                            "flavor_part": "HOST_UNIQUE",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED_IF_DEFINED"
//                            }
//                        }
//                    ]
//                },
//                "flavor_ids": [
//                    "b37580dd-f300-4229-8358-2640936c3841"
//                ]
//            }
//        ]
//    }

// ---

// swagger:operation POST /flavorgroups Flavorgroups Create
// ---
//
// description: |
//   Creates a flavor group.
//
//   The serialized Flavorgroup Go struct object represents the content of the request body.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | name                           | Name of the flavorgroup to be created. |
//    | flavor_match_policy_collection | Collection of flavor match policies. Each flavor match policy contains two <br> parts: <br><b>flavor_part</b>:The type or classification of the flavor.<br> <b>match_policy</b>:The policy which defines how the host is verified against the <br> flavors in the flavor group for the specified flavor part. |
//    | flavorTemplateIds              | (Optional) Flavor template ids that the created flavorgroup will be associated with. If not provided, created flavorgroup will be associated with all the templates associated with the automatic flavor group. |
//
// x-permissions: flavorgroups:create
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
//    "$ref": "#/definitions/FlavorGroup"
// - name: Content-Type
//   required: true
//   in: header
//   type: string
// - name: Accept
//   required: true
//   in: header
//   type: string
// responses:
//   '201':
//     description: Successfully created the flavorgroup.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorGroup"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups
// x-sample-call-input: |
//    {
//        "name":"CustomerX",
//        "flavor_match_policy_collection": {
//            "flavor_match_policies": [
//               {
//                   "flavor_part": "PLATFORM",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "OS",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "ASSET_TAG",
//                   "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//               },
//               {
//                   "flavor_part": "HOST_UNIQUE",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED_IF_DEFINED"
//                   }
//               }
//           ]
//        }
//    }
// x-sample-call-output: |
//    {
//        "id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
//        "name":"CustomerX",
//        "flavor_match_policy_collection":{
//            "flavor_match_policies": [
//               {
//                   "flavor_part": "PLATFORM",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "OS",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "ASSET_TAG",
//                   "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//               },
//               {
//                   "flavor_part": "HOST_UNIQUE",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED_IF_DEFINED"
//                   }
//               }
//           ]
//        }
//    }

// ---

// swagger:operation GET /flavorgroups/{flavorgroup_id} Flavorgroups Retrieve
// ---
//
// description: |
//   Retrieves a flavor group.
//   Returns - The serialized Flavorgroup Go struct object that was retrieved and a list of associated flavor IDs
// x-permissions: flavorgroups:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
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
//     description: Successfully retrieved the flavorgroup.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorGroup"
//   '404':
//     description: Flavorgroup record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/826501bd-3c75-4839-a08f-db5f744f8498
// x-sample-call-output: |
//    {
//        "id": "826501bd-3c75-4839-a08f-db5f744f8498",
//        "name": "automatic",
//        "flavor_match_policy_collection": {
//            "flavor_match_policies": [
//                {
//                    "flavor_part": "PLATFORM",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED"
//                    }
//                },
//                {
//                    "flavor_part": "OS",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED"
//                    }
//                },
//                {
//                    "flavor_part": "ASSET_TAG",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//                },
//                {
//                    "flavor_part": "HOST_UNIQUE",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//                }
//            ]
//        },
//        "flavor_ids": [
//            "b37580dd-f300-4229-8358-2640936c3841"
//        ]
//    }

// ---

// swagger:operation DELETE /flavorgroups/{flavorgroup_id} Flavorgroups Delete
// ---
//
// description: |
//   Deletes a flavor group. If the flavor group is still associated with any hosts, an error will be thrown.
// x-permissions: flavorgroups:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the Flavorgroup.
//   '404':
//     description: Flavorgroup record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/826501bd-3c75-4839-a08f-db5f744f8498
// ---

// swagger:operation POST /flavorgroups/{flavorgroup_id}/flavors  Flavorgroups  Create-FlavorLink
// ---
//
// description: |
//   Creates an association between a Flavor and FlavorGroup record.
//
//   The serialized FlavorgroupFlavorLinkCriteria Go struct object represents the content of the request body.
//
//    | Attribute                      | Description                                               |
//    |--------------------------------|-----------------------------------------------------------|
//    | flavor_id                      | ID of the Flavor record to be linked with the FlavorGroup |
//
//
//
// x-permissions: flavorgroups:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: flavorgroup_id
//   required: true
//   in: path
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/FlavorgroupFlavorLinkCriteria"
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
//     description: Successfully linked the FlavorGroup and Flavor.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorgroupFlavorLink"
//   '400':
//     description: Invalid request body provided/FlavorID provided in request body does not exist/FlavorGroup-Flavor link already exists
//   '404':
//     description: FlavorGroup ID in request path does not exist
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/8d7964db-4e4d-49a0-b441-1beabbcebf78/flavors
// x-sample-call-input: |
//    {
//        "flavor_id":"1429cebf-1c09-4e78-b2aa-da10e58d7446",
//    }
// x-sample-call-output: |
//   {
//     "flavorgroup_id": "8d7964db-4e4d-49a0-b441-1beabbcebf78",
//     "flavor_id": "1429cebf-1c09-4e78-b2aa-da10e58d7446"
//   }

// ---

// swagger:operation GET /flavorgroups/{flavorgroup_id}/flavors/{flavor_id}  Flavorgroups  Retrieve-Flavorlink
// ---
//
// description: |
//   Retrieves a FlavorGroup-Flavor association.
//   Returns - The FlavorGroupFlavorLink in JSON format that represents the association.
// x-permissions: flavorgroups:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_id
//   description: Unique ID of the flavor.
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
//     description: Successfully retrieved the FlavorGroupFlavorLink.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorgroupFlavorLink"
//   '404':
//     description: Flavorgroup/Flavor record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/8d7964db-4e4d-49a0-b441-1beabbcebf78/flavors/1429cebf-1c09-4e78-b2aa-da10e58d7446
// x-sample-call-output: |
//  {
//    "flavorgroup_id": "8d7964db-4e4d-49a0-b441-1beabbcebf78",
//    "flavor_id": "1429cebf-1c09-4e78-b2aa-da10e58d7446"
//  }

// ---

// swagger:operation DELETE /flavorgroups/{flavorgroup_id}/flavors/{flavor_id}  Flavorgroups  Delete-FlavorLink
// ---
//
// description: |
//   Deletes an individual FlavorGroup Flavor link.
// x-permissions: flavorgroups:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the Flavorgroup-Flavor link.
//   '404':
//     description: Flavorgroup/Flavor record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/826501bd-3c75-4839-a08f-db5f744f8498
// ---

// swagger:operation GET /flavorgroups/{flavorgroup_id}/flavors Flavorgroups Search-Flavorlinks
// ---
//
// description: |
//   Retrieves a list of FlavorGroup-Flavor associations corresponding to a flavorgroup.
//   Returns - The FlavorgroupFlavorLinkCollection in JSON format that are associated with the flavorgroup.
// x-permissions: flavorgroups:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
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
//     description: Successfully retrieved the FlavorgroupFlavorLinkCollection.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorgroupFlavorLinkCollection"
//   '404':
//     description: Flavorgroup record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/e5574593-0f92-41f0-8f2d-93b97cea9c06/flavors
// x-sample-call-output: |
//  {
//  "flavor_flavorgroup_links": [
//  {
//  "flavorgroup_id": "e5574593-0f92-41f0-8f2d-93b97cea9c06",
//  "flavor_id": "fdd4240b-2369-4175-80e7-7fbf8ec78ce8"
//  },
//  {
//  "flavorgroup_id": "e5574593-0f92-41f0-8f2d-93b97cea9c06",
//  "flavor_id": "bf8a9882-8a49-43ca-8052-b666bd7c0172"
//  }
//  ]
//  }
