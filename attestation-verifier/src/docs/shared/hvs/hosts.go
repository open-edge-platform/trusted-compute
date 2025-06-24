/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// Host response payload
// swagger:parameters Host
type Host struct {
	// in:body
	Body hvs.Host
}

// HostCollection response payload
// swagger:parameters HostCollection
type HostCollection struct {
	// in:body
	Body hvs.HostCollection
}

// Host request payload
// swagger:parameters HostCreateRequest
type HostCreateRequest struct {
	// in:body
	Body hvs.HostCreateRequest
}

// HostFlavorgroup response payload
// swagger:parameters HostFlavorgroup
type HostFlavorgroup struct {
	// in:body
	Body hvs.HostFlavorgroup
}

// HostFlavorgroupCollection response payload
// swagger:parameters HostFlavorgroupCollection
type HostFlavorgroupCollection struct {
	// in:body
	Body hvs.HostFlavorgroupCollection
}

// HostFlavorgroup request payload
// swagger:parameters HostFlavorgroupCreateRequest
type HostFlavorgroupCreateRequest struct {
	// in:body
	Body hvs.HostFlavorgroupCreateRequest
}

// ---

// swagger:operation POST /hosts Hosts CreateHost
// ---
//
// description: |
//   <b>Host Connection String</b>
//   <pre>
//   For Intel hosts, this would have the vendor name, the IP addresses, or DNS host name. e.g.:
//   "intel:https://trustagent.server.com:1443"</br>
//   For VMware, this includes the vCenter and host IP address or DNS host name and credentials. e.g.:
//   "vmware:https://vCenterServer.com:443/sdk;h=trustagent.server.com;u=vCenterUsername;p=vCenterPassword"</br>
//   </pre>
//
//   <b>Creates a host.</b>
//   <pre>
//   A connection string and name for the host must be specified. This name is the value the Host Verification Service (HVS) uses to keep track of the host. It does not have to be the actual host name or IP address of the server.</br>
//   If a flavor group is not specified, the host created will be assigned to the default “automatic” flavor group. If a flavor group is specified and does not already exist, it will be created with a default flavor match policy.</br>
//   Once the host is created, it is added to the flavor verification queue in backend.</br>
//   </pre>
//
//   The serialized HostCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute         | Description |
//    |-------------------|-------------|
//    | host_name         | HVS name for the host. |
//    | connection_string | The host connection string. |
//    | flavorgroup_names | List of flavor group names that the created host will be associated. |
//    | description       | Host description. |
//
// x-permissions: hosts:create
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
//    "$ref": "#/definitions/HostCreateRequest"
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
//     description: Successfully created the host.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Host"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts
// x-sample-call-input: |
//    {
//        "host_name": "Purley host1",
//        "connection_string": "intel:https://trustagent.server.com:1443",
//        "flavorgroup_names": [""],
//        "description": "RHEL TPM2.0 Purley"
//    }
// x-sample-call-output: |
//    {
//        "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "host_name":"Purley host1",
//        "description": "RHEL TPM2.0 Purley",
//        "connection_string": "https://trustagent.server.com:1443",
//        "hardware_uuid": "80ecce40-04b8-e811-906e-00163566263e",
//        "flavorgroup_names": [
//            "automatic", "platform_software"
//        ]
//    }

// ---

// swagger:operation GET /hosts/{host_id} Hosts RetrieveHost
// ---
//
// description: |
//   Retrieves a host.
//   Returns - The serialized Host Go struct object that was retrieved.
// x-permissions: hosts:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: host_id
//   description: Unique ID of the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: getReport
//   description: Fetch platform data for the host as well.
//   in: query
//   type: boolean
// - name: getHostStatus
//   description: Fetch host status for the host as well.
//   in: query
//   type: boolean
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the host.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Host"
//   '404':
//     description: Host record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-output: |
//    {
//        "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "host_name": "Purley host1",
//        "description": "RHEL TPM2.0 Purley",
//        "connection_string": "https://trustagent.server.com:1443",
//        "hardware_uuid": "80ecce40-04b8-e811-906e-00163566263e"
//        "flavorgroup_names": [
//            "automatic", "platform_software"
//        ]
//    }
//
// ---

// swagger:operation PUT /hosts/{host_id} Hosts UpdateHost
// ---
//
// description: |
//   Updates a host.
//
//   The serialized Host Go struct object represents the content of the request body.
//
//    | Attribute         | Description |
//    |-------------------|-------------|
//    | host_name         | Complete name of the host. |
//    | hardware_uuid     | Hardware UUID of the host. |
//    | connection_string | The host connection string. |
//    | flavorgroup_names | List of flavor group names that the created host will be associated. |
//    | description       | Host description. |
//
//
//
// x-permissions: hosts:store
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: host_id
//   description: Unique ID of the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/Host"
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
//   '200':
//     description: Successfully updated the host.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Host"
//   '400':
//     description: Invalid request body provided
//   '404':
//     description: Host record not found
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-input: |
//    {
//        "host_name": "Purley host2",
//        "description": "RHEL TPM2.0 Purley Host"
//    }
// x-sample-call-output: |
//    {
//        "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "host_name":"Purley host2",
//        "description": "RHEL TPM2.0 Purley Host",
//        "connection_string": "https://trustagent.server.com:1443",
//        "hardware_uuid": "80ecce40-04b8-e811-906e-00163566263e",
//        "flavorgroup_names": [
//            "automatic", "platform_software"
//        ]
//    }

// ---

// swagger:operation DELETE /hosts/{host_id} Hosts DeleteHost
// ---
//
// description: |
//   Deletes a host.
// x-permissions: hosts:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: host_id
//   description: Unique ID of the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   required: true
//   in: header
//   type: string
// responses:
//   '204':
//     description: Successfully deleted the host.
//   '404':
//     description: Host record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e

// ---

// swagger:operation GET /hosts Hosts SearchHost
// ---
//
// description: |
//   <b>Host</b>
//   <pre>
//   A host is a datacenter server. When a host is created, the connection details are specified and it is associated with a flavor group. The host will be continually monitored against the flavors in the respective flavor group, and the trust status will be updated accordingly.</br>
//   </pre>
//
//   <b>Searches for hosts.</b>
//   <pre>
//   Only one identifying parameter can be specified. The parameters listed here are in the order of priority that will be evaluated.</br>
//   </pre>
//
//   Returns - The serialized HostCollection Go struct object that was retrieved, which is a collection of serialized Host Go struct objects.
//
// x-permissions: hosts:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Host ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: nameEqualTo
//   description: Host name.
//   in: query
//   type: string
//   required: false
// - name: nameContains
//   description: Substring of host name.
//   in: query
//   type: string
//   required: false
// - name: hostHardwareId
//   description: Hardware UUID of host.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: key
//   description: User needs to specify values for both key and value fields. Key can be any field in host info section of host report field in host status table.
//   in: query
//   type: string
//   required: false
// - name: value
//   description: User needs to specify values for both key and value fields. Value will be content of key field in host info section of host report field in host status table.
//   in: query
//   type: string
//   required: false
// - name: trusted
//   description: Get host by trust status.
//   in: query
//   type: boolean
//   required: false
// - name: getTrustStatus
//   description: Get trust status for host.
//   in: query
//   type: boolean
//   required: false
// - name: getHostStatus
//   description: Get status of host.
//   in: query
//   type: boolean
//   required: false
// - name: orderBy
//   description: Orders the host collection in ascending/descending order. Accepted values are "asc"/"desc" the default being "asc".
//   in: query
//   type: string
//   enum:
//      - asc
//      - desc
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
//     description: Successfully retrieved the hosts.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/HostCollection"
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts
// x-sample-call-output: |
//    {
//        "hosts": [
//            {
//                "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//                "host_name": "Purley host1",
//                "description": "RHEL TPM2.0 Purley",
//                "connection_string": "https://trustagent.server.com:1443",
//                "hardware_uuid": "80ecce40-04b8-e811-906e-00163566263e"
//                "flavorgroup_names": [
//                    "automatic", "platform_software"
//                ]
//            }
//        ]
//    }
//
// ---

// swagger:operation POST /hosts/{host_id}/flavorgroups HostFlavorgroupLinks CreateHostFlavorgroupLink
// ---
//
// description: |
//   Associates the host with the flavorgroup specified in HostFlavorgroupCreateRequest Go struct object.</br>
//   Once the host is associated, it is added to the flavor verification queue in backend.
//
//   The serialized HostFlavorgroupCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute      | Description |
//    |----------------|-------------|
//    | flavorgroup_id | Unique ID of the flavorgroup to be linked to host. |
//
//
//
// x-permissions: hosts:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: host_id
//   description: Unique ID of the host to be linked to the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/HostFlavorgroupCreateRequest"
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
//     description: Successfully created the host flavorgroup link.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/HostFlavorgroup"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error

//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/{host_id}/flavorgroups
// x-sample-call-input: |
//    {
//        "flavorgroup_id": "c96da83d-b202-49b0-b266-fc6018883e12"
//    }
// x-sample-call-output: |
//    {
//        "host_id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "flavorgroup_id": "c96da83d-b202-49b0-b266-fc6018883e12"
//    }

// ---

// swagger:operation GET /hosts/{host_id}/flavorgroups/{flavorgroup_id} HostFlavorgroupLinks RetrieveHostFlavorgroupLink
// ---
//
// description: |
//   Retrieves a host-flavorgroup link.
//   Returns - The serialized HostFlavorgroup Go struct object that was retrieved.
// x-permissions: hosts:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: host_id
//   description: Unique ID of the host for which the host-flavorgroup association needs to be retrieved.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup for which the host-flavorgroup association needs to be retrieved.
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
//     description: Successfully retrieved the host flavorgroup link.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/HostFlavorgroup"
//   '404':
//     description: Flavorgroup record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/flavorgroups/c96da83d-b202-49b0-b266-fc6018883e12
// x-sample-call-output: |
//    {
//        "host_id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "flavorgroup_id": "c96da83d-b202-49b0-b266-fc6018883e12"
//    }

// ---

// swagger:operation DELETE /hosts/{host_id}/flavorgroups/{flavorgroup_id} HostFlavorgroupLinks DeleteHostFlavorgroupLink
// ---
//
// description: |
//   Deletes the link between the host and the flavorgroup.
// x-permissions: hosts:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: host_id
//   description: Unique ID of the host that need to be dissociated from the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup that need to be dissociated from the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the host flavorgroup link.
//   '404':
//     description: Flavorgroup record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/flavorgroups/c96da83d-b202-49b0-b266-fc6018883e12

// ---

// swagger:operation GET /hosts/{host_id}/flavorgroups HostFlavorgroupLinks SearchHostFlavorgroupLink
// ---
//
// description: |
//   Search host-flavorgroup links using host ID.
//   Returns - The serialized HostFlavorgroupCollection Go struct object that was retrieved, which is a collection of serialized HostFlavorgroup Go struct objects.
//
// x-permissions: hosts:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: host_id
//   description: Unique ID of the host for which the host-flavorgroup association needs to be retrieved.
//   in: path
//   type: string
//   format: uuid
//   required: true
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the host flavorgroup links.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/HostFlavorgroupCollection"
//   '404':
//     description: Flavorgroup record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/hosts/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/flavorgroups
// x-sample-call-output: |
//    {
//        "flavorgroup_host_links": [
//            {
//                "host_id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//                "flavorgroup_id": "c96da83d-b202-49b0-b266-fc6018883e12"
//            }
//        ]
//    }
