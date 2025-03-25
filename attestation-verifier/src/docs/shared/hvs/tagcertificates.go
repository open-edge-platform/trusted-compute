/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

// TagCertificate response payload
// swagger:parameters TagCertificate
type TagCertificate struct {
	// in:body
	Body hvs.TagCertificate
}

// TagCertificateCreateCriteria request payload
// swagger:parameters TagCertificateCreateCriteria
type TagCertificateCreateCriteria struct {
	// in:body
	Body models.TagCertificateCreateCriteria
}

// TagCertificateDeploy request payload
// swagger:parameters TagCertificateDeployCriteria
type TagCertificateDeployCriteria struct {
	// in:body
	Body models.TagCertificateDeployCriteria
}

// TagCertificateCollection response payload
// swagger:parameters TagCertificateCollection
type TagCertificateCollection struct {
	// in:body
	Body hvs.TagCertificateCollection
}

//
// swagger:operation GET /tag-certificates TagCertificates SearchTagCertificates
// ---
//
// description: |
//   Searches for Tag Certificates.
//   Returns - The serialized TagCertificateCollection Go struct object that was retrieved, which is a collection of serialized TagCertificate Go struct objects.
//
//   <b>Note</b>
//   Only one identifying parameter can be specified. The parameters listed here are in the order of priority that will be evaluated.
//
// x-permissions: tag_certificates:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: TagCertificate ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: subjectEqualTo
//   description: TagCertificate subject strict match.
//   in: query
//   type: string
//   required: false
// - name: subjectContains
//   description: Substring of TagCertificate subject.
//   in: query
//   type: string
//   required: false
// - name: issuerEqualTo
//   description: TagCertificate issuer strict match.
//   in: query
//   type: string
//   required: false
// - name: issuerContains
//   description: Substring of TagCertificate issuer.
//   in: query
//   type: string
//   required: false
// - name: validOn
//   description: Filters TagCertificates that are valid on this date.
//   in: query
//   type: string
//   format: date-time
//   required: false
// - name: validBefore
//   description: Filters TagCertificates that are valid before this date.
//   in: query
//   type: string
//   format: date-time
//   required: false
// - name: validAfter
//   description: Filters TagCertificates that are valid after this date.
//   in: query
//   type: string
//   format: date-time
//   required: false
// - name: hardwareUuid
//   description: Hardware UUID of the Tag Certificate
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
//
// responses:
//   '200':
//     description: Successfully retrieved the Tag Certificates. Returns an empty list when no matching records are found.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/TagCertificateCollection"
//   '400':
//     description: Invalid value for filter criteria.
//   '415':
//     description: Invalid Accept Header in Request
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tag-certificates?hardwareUUID=00ecd3ab-9af4-e711-906e-001560a04062
// x-sample-call-output: |
//    {
//        "certificates": [
//            {
//                "id": "ec7a9f98-0c79-4856-994c-b1a2087d03d1",
//                "certificate": "MIIEQTCCAqmgAwIBAgIQVGCFNpSOXMOmAC9Hh/wd1TANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDAwZWNkM2FiLTlhZjQtZTcxMS05MDZlLTAwMTU2MGEwNDA2MjAeFw0yMDA3MjAxMzU1MDBaFw0yMTA3MjAxMzU1MDBaMDExLzAtBgNVBAMMJhMkMDBlY2QzYWItOWFmNC1lNzExLTkwNmUtMDAxNTYwYTA0MDYyMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtnabBETKFz93lR/w9cnfyuoYfeDneq2r8uT9OXW5ZuLMym6oTJh7XipHQVWWmifg6ShMQBbkWOie9h8viK1FqiPnkzdEvyS0LX++s4nvfPZY6d+hMWxGL3BVG7k7nZLK1l2vc3SwOE9P1oBonjWwGYV91Uh9z32oN6j/m1HQtIYiYRGv7WctYDL4jWoGmMGQPbLIpz0XOD61U4Muo196xxp1SgdRcc0BHDt5zKqSlrWW6el0Ookb/GsZSIQ80SKT+mGjBBS0Sd/sWlyLABCHNZroZ+rFcR3RN2y05X94pq0iGcJNjNm0DzVfU1Me+lCJNX16cJo6aFbcSVZm1i+tOayeEjMcmeNk6s6Vt7CrmqtIVeWFKmJ6sutbb1yYOSDPH8gg0iJuxc8JoRET0pTE3COAq5LCyh2YG5v/OckmaogeyIFkK4dyoxvYTmjhvklme2Vp+8kQMFUyHAtF2ij2Px0ZaX6jOJbDDb9g0MsE2Yzrv3Vmw4tnLt9p4EST0k71AgMBAAGjVTBTMCMGBVUEhhUBAQH/BBcwFRMITG9jYXRpb24TCU5vcnRoUG9sZTAsBgVVBIYVAQEB/wQgMB4TB0NvbXBhbnkTE1NhbnRhQ2xhdXNlV29ya3Nob3AwDQYJKoZIhvcNAQEMBQADggGBAA5FMy2NGjZmqldsk7ZpPwWBf90aClmJTzww7HpWxPUr4YEAnWpVgay6XH+wYt9r5YkMBsbPv6sZ1U1IRcy9qDY2O2PuyiE8OfxHsndps1VEQpmX+NHClGpmX49z1/DfA6UB96vMW2w+Yewh/RnNL+P2IyvTrSG+foZA/zPQgX2PzSVYlG3w8GZhb9oY6m5k8RuRkTqJ2IJfMZsd31XwsPfEsh3sIQ8o8bSj/aZYS+LDfMD06qjSEsNJ0HUyPKTN9SQMFslaGU0oQc9a6FEGWrew2Bx5TnrEse6+qpyKh+tZUp+yxod29gTCN0oGj7lcry/sUlqKA6CenXfYUk6GLXSgrPeU7B7GACXX5VDBMRIuU/Pzy7I+rzqi3/w5OtCCE8iMgcEyIbjDRGyxaM0fsJxeXXlXdb/nuc7x+g8vqsHvWG05ITNYgJww+ePRhi2OPg0L3e3TIHLOT0+DP2VdNysXitCiVt9Y9jeu5j3XTc5ZElERsVCLGGqTZA7FzY3GcA==",
//                "subject": "00ecd3ab-9af4-e711-906e-001560a04062",
//                "issuer": "HVS Tag Certificate",
//                "not_before": "2020-07-20T13:55:00Z",
//                "not_after": "2021-07-20T13:55:00Z",
//                "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//                "asset_tag_digest": "LyAgoHDmNoCxIBvrkDnv+neoXHd3hefsUU5ZQpPOMq4bgW/qBKNIhm16LZwEaVxb"
//            },
//            {
//                "id": "0d18daf4-5daa-4b5b-94fd-8c6848632dff",
//                "certificate": "MIIEQjCCAqqgAwIBAgIRAJd7560Tn7333DjilFwC3g8wDQYJKoZIhvcNAQEMBQAwMTEvMC0GA1UEAwwmEyQwMGVjZDNhYi05YWY0LWU3MTEtOTA2ZS0wMDE1NjBhMDQwNjIwHhcNMjAwNzIwMTgzOTEwWhcNMjEwNzIwMTgzOTEwWjAxMS8wLQYDVQQDDCYTJDAwZWNkM2FiLTlhZjQtZTcxMS05MDZlLTAwMTU2MGEwNDA2MjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALZ2mwREyhc/d5Uf8PXJ38rqGH3g53qtq/Lk/Tl1uWbizMpuqEyYe14qR0FVlpon4OkoTEAW5FjonvYfL4itRaoj55M3RL8ktC1/vrOJ73z2WOnfoTFsRi9wVRu5O52SytZdr3N0sDhPT9aAaJ41sBmFfdVIfc99qDeo/5tR0LSGImERr+1nLWAy+I1qBpjBkD2yyKc9Fzg+tVODLqNfescadUoHUXHNARw7ecyqkpa1lunpdDqJG/xrGUiEPNEik/phowQUtEnf7FpciwAQhzWa6GfqxXEd0TdstOV/eKatIhnCTYzZtA81X1NTHvpQiTV9enCaOmhW3ElWZtYvrTmsnhIzHJnjZOrOlbewq5qrSFXlhSpierLrW29cmDkgzx/IINIibsXPCaERE9KUxNwjgKuSwsodmBub/znJJmqIHsiBZCuHcqMb2E5o4b5JZntlafvJEDBVMhwLRdoo9j8dGWl+oziWww2/YNDLBNmM6791ZsOLZy7faeBEk9JO9QIDAQABo1UwUzAjBgVVBIYVAQEB/wQXMBUTCExvY2F0aW9uEwlTb3V0aFBvbGUwLAYFVQSGFQEBAf8EIDAeEwdDb21wYW55ExNTYW50YUNsYXVzZVdvcmtzaG9wMA0GCSqGSIb3DQEBDAUAA4IBgQCIDffmRt8omq0mEFx+VXDHhUuQrYVWzJr8MLCRnjyZYtPaXmanJWP7YjLrddSzeF1Gd5saiQBsm6Q/vqegF98+2g18BUz4cCt9/vcZptwuUNr/zqnAsKJ/eGkz12t845QiX6O/E4IUaBaxay1t7qLpcR3c5J++wYfFKtd2FnV2hz/exu2DTFfseh4iX85QzyOZuMtzRaACjq0yNuX+yja5v++966RbwXz2c1eDGkC8r1mus/HgF1WrIcZmMWtFQtRiTe70OxMf6y7dSy8Dv4Aqad5ME/CR0MBaTSfYpLpa1+8lZodp6fQJ2dj6CXq0opHOTYBNDvs/Cs5BdqXoK7rGuWCxdhM6AENAVmL6S62Yt+vi21AKGxdO1s7Eq5LrI1JMS9NMeVU/ythsAetki48Yl1IDAfeNwLquw6VXdHypE0YLv1iOjNu9sbXkadyDony7t9ko/kDDnoYTLM1KuLzKCO2bEyUIudtNeH8Jw/sggY92d17OHOvrBXdTDnfRvwc=",
//                "subject": "00ecd3ab-9af4-e711-906e-001560a04062",
//                "issuer": "HVS Tag Certificate",
//                "not_before": "2020-07-20T18:39:10Z",
//                "not_after": "2021-07-20T18:39:10Z",
//                "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//                "asset_tag_digest": "SQ0G0q/0YHpeqAScfQUq83luo3Qkqm9eJHx9AL0Qfo8ThM5boB0XWz57GcWOfdc+"
//            }
//        ]
//    }
// ---

// ---

// swagger:operation POST /tag-certificates TagCertificates CreateTagCertificate
// ---
//
// description: |
//   Creates an Asset Tag Certificate.
//
//   An "Asset Tag" is a host-specific certificate created with a set of
//   user-defined key/value pairs that can be used to "tag" a server at
//   the hardware level. Asset Tags are included in host attestation, verifying
//   that, if an Asset Tag has been deployed to a host, that the correct
//   Tag is included in the host's TPM Quote.
//   Attestation Reports will display the key/value pairs associated with the Asset Tag, and can be used by
//   scheduler services or compliance audit reporting.  One typical use case for Asset Tags is "geolocation tagging",
//   tagging each host with key/value pairs matching the physical location of the host.
//
//   The serialized TagCertificateCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute         | Description |
//    |-------------------|-------------|
//    | hardware_uuid     | The hardware UUID of the host to which the tag certificate is associated. |
//    | selection_content | an array of one or more key-value pairs with the tag selection attributes. |
//
//
//
// x-permissions: tag_certificates:create
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
//    $ref: "#/definitions/TagCertificateCreateCriteria"
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
//     description: Successfully created the Tag Certificate.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/TagCertificate"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tag-certificates
// x-sample-call-input: |
//    {
//        "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//        "selection_content": [
//            {
//                "name": "Location",
//                "value": "SouthPole"
//            },
//            {
//                "name": "Company",
//                "value": "SantaClauseWorkshop"
//            }
//        ]
//    }
// x-sample-call-output: |
//    {
//        "id": "0d18daf4-5daa-4b5b-94fd-8c6848632dff",
//        "certificate": "MIIEQjCCAqqgAwIBAgIRAJd7560Tn7333DjilFwC3g8wDQYJKoZIhvcNAQEMBQAwMTEvMC0GA1UEAwwmEyQwMGVjZDNhYi05YWY0LWU3MTEtOTA2ZS0wMDE1NjBhMDQwNjIwHhcNMjAwNzIwMTgzOTEwWhcNMjEwNzIwMTgzOTEwWjAxMS8wLQYDVQQDDCYTJDAwZWNkM2FiLTlhZjQtZTcxMS05MDZlLTAwMTU2MGEwNDA2MjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALZ2mwREyhc/d5Uf8PXJ38rqGH3g53qtq/Lk/Tl1uWbizMpuqEyYe14qR0FVlpon4OkoTEAW5FjonvYfL4itRaoj55M3RL8ktC1/vrOJ73z2WOnfoTFsRi9wVRu5O52SytZdr3N0sDhPT9aAaJ41sBmFfdVIfc99qDeo/5tR0LSGImERr+1nLWAy+I1qBpjBkD2yyKc9Fzg+tVODLqNfescadUoHUXHNARw7ecyqkpa1lunpdDqJG/xrGUiEPNEik/phowQUtEnf7FpciwAQhzWa6GfqxXEd0TdstOV/eKatIhnCTYzZtA81X1NTHvpQiTV9enCaOmhW3ElWZtYvrTmsnhIzHJnjZOrOlbewq5qrSFXlhSpierLrW29cmDkgzx/IINIibsXPCaERE9KUxNwjgKuSwsodmBub/znJJmqIHsiBZCuHcqMb2E5o4b5JZntlafvJEDBVMhwLRdoo9j8dGWl+oziWww2/YNDLBNmM6791ZsOLZy7faeBEk9JO9QIDAQABo1UwUzAjBgVVBIYVAQEB/wQXMBUTCExvY2F0aW9uEwlTb3V0aFBvbGUwLAYFVQSGFQEBAf8EIDAeEwdDb21wYW55ExNTYW50YUNsYXVzZVdvcmtzaG9wMA0GCSqGSIb3DQEBDAUAA4IBgQCIDffmRt8omq0mEFx+VXDHhUuQrYVWzJr8MLCRnjyZYtPaXmanJWP7YjLrddSzeF1Gd5saiQBsm6Q/vqegF98+2g18BUz4cCt9/vcZptwuUNr/zqnAsKJ/eGkz12t845QiX6O/E4IUaBaxay1t7qLpcR3c5J++wYfFKtd2FnV2hz/exu2DTFfseh4iX85QzyOZuMtzRaACjq0yNuX+yja5v++966RbwXz2c1eDGkC8r1mus/HgF1WrIcZmMWtFQtRiTe70OxMf6y7dSy8Dv4Aqad5ME/CR0MBaTSfYpLpa1+8lZodp6fQJ2dj6CXq0opHOTYBNDvs/Cs5BdqXoK7rGuWCxdhM6AENAVmL6S62Yt+vi21AKGxdO1s7Eq5LrI1JMS9NMeVU/ythsAetki48Yl1IDAfeNwLquw6VXdHypE0YLv1iOjNu9sbXkadyDony7t9ko/kDDnoYTLM1KuLzKCO2bEyUIudtNeH8Jw/sggY92d17OHOvrBXdTDnfRvwc=",
//        "subject": "00ecd3ab-9af4-e711-906e-001560a04062",
//        "issuer": "HVS Tag Certificate",
//        "not_before": "2020-07-20T18:39:10Z",
//        "not_after": "2021-07-20T18:39:10Z",
//        "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//        "asset_tag_digest": "SQ0G0q/0YHpeqAScfQUq83luo3Qkqm9eJHx9AL0Qfo8ThM5boB0XWz57GcWOfdc+"
//    }

// ---
//
// swagger:operation DELETE /tag-certificates/{tagcertificate_id} TagCertificates DeleteTagCertificate
// ---
//
// description: |
//   Deletes a Tag Certificate.
// x-permissions: tag_certificates:delete
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: tagcertificate_id
//   description: Unique ID of the Tag Certificate.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the Tag Certificate.
//   '404':
//     description: TagCertificate does not exist
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tag-certificates/fc0cc779-22b6-4741-b0d9-e2e69635ad1e

// ---
//
// swagger:operation POST /rpc/deploy-tag-certificate TagCertificates DeployTagCertificate
// ---
//
// description: |
//   Deploys a Tag Certificate to a connected host.
//
//   The serialized TagCertificateDeployCriteria Go struct object represents the content of the request body.
//
//    | Attribute         | Description |
//    |-------------------|-------------|
//    | certificate_id    | ID of TagCertificate to be deployed. |
//
//
//
// x-permissions: tag_certificates:deploy
// security:
//  - bearerAuth: []
// consumes:
// - application/json
// produces:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     $ref: "#/definitions/TagCertificateDeployCriteria"
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
//     description: Successfully deployed the TagCertificate to the host.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavor"
//   '400':
//     description: Error decoding the TagCertificateDeployCriteria.
//   '404':
//     description: TagCertificate does not exist.
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Error deploying the TagCertificate.
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/rpc/deploy-tag-certificate
// x-sample-call-input: |
//    {
//        "certificate_id": "ec7a9f98-0c79-4856-994c-b1a2087d03d1"
//    }
// x-sample-call-output: |
//      {
//          "flavor": {
//              "meta": {
//                  "id": "ccd8790e-f707-43a4-9f8a-2446ca2dfc63",
//                  "description": {
//                      "flavor_part": "ASSET_TAG",
//                      "source": "computepurley",
//                      "label": "INTEL_00ecd3ab-9af4-e711-906e-001560a04062_2020-07-22T21:06:02.187002-07:00",
//                      "tpm_version": "2.0",
//                      "hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
//                      "tboot_installed": "true"
//                  },
//                  "vendor": "INTEL"
//              },
//              "bios": {
//                  "bios_name": "Intel Corporation",
//                  "bios_version": "SE5C620.86B.00.01.0015.110720180833"
//              },
//              "external": {
//                  "asset_tag": {
//                      "tag_certificate": {
//                          "encoded": "MIIEFzCCAn+gAwIBAgIRAPevjWFSqf36WgtDrLMiCvwwDQYJKoZIhvcNAQEMBQAwHjEcMBoGA1UEAxMTSFZTIFRhZyBDZXJ0aWZpY2F0ZTAeFw0yMDA3MjIxNjM5NTVaFw0yMTA3MjIxNjM5NTVaMC8xLTArBgNVBAMTJDAwZWNkM2FiLTlhZjQtZTcxMS05MDZlLTAwMTU2MGEwNDA2MjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALZ2mwREyhc/d5Uf8PXJ38rqGH3g53qtq/Lk/Tl1uWbizMpuqEyYe14qR0FVlpon4OkoTEAW5FjonvYfL4itRaoj55M3RL8ktC1/vrOJ73z2WOnfoTFsRi9wVRu5O52SytZdr3N0sDhPT9aAaJ41sBmFfdVIfc99qDeo/5tR0LSGImERr+1nLWAy+I1qBpjBkD2yyKc9Fzg+tVODLqNfescadUoHUXHNARw7ecyqkpa1lunpdDqJG/xrGUiEPNEik/phowQUtEnf7FpciwAQhzWa6GfqxXEd0TdstOV/eKatIhnCTYzZtA81X1NTHvpQiTV9enCaOmhW3ElWZtYvrTmsnhIzHJnjZOrOlbewq5qrSFXlhSpierLrW29cmDkgzx/IINIibsXPCaERE9KUxNwjgKuSwsodmBub/znJJmqIHsiBZCuHcqMb2E5o4b5JZntlafvJEDBVMhwLRdoo9j8dGWl+oziWww2/YNDLBNmM6791ZsOLZy7faeBEk9JO9QIDAQABoz8wPTAeBgVVBIYVAQQVMBMTCExvY2F0aW9uEwdWaWV0bmFtMBsGBVUEhhUBBBIwEBMHQ29tcGFueRMFSW50ZWwwDQYJKoZIhvcNAQEMBQADggGBABXiz70tGfke0yAY/2EOsqcBoLbfRBGxHJydYGkiJO2CMt5IF4fS4wu2q5vypTHWuhRa+CduacMICys4oUPCzAvR+vW5h5zLL5wisSLT4hprS2LDP1HAV/58115GGz+NZRIpixBMSsxuf1bEawxAH6pJz7PxLzSMetxS1Wc7R9CPiHMnQf9KNVfSO88O0wehjfJteNanLTSYYKK58/yeQWLzQHTKbjHWKVM+LDBNMK/lD+0DfAiRASJGhPyMX+EVn6zz3JEl7263fOWVSKf39OEB6ghIam9xhZZauhcz520LQGsPFduG0KyOQVD6h7ChXm7EVsPWqsJs034yqAhRkFmoDWeFl6zQhpxI28W1loBgEvWKofAIVQDaR8Ao0z535Vquw7hsanudpqbOs4TcOPPF12kGk3Q0TNBt+2vIRZih2ZA/UC1qHALDGcDVV81wC545i5Hwdu6SPbdLmPhmJ71718W2A8a4oTar/lhZlN6NggdfxXhQHFhlJ/ftOs+UBw==",
//                          "issuer": "CN=HVS Tag Certificate",
//                          "serial_number": 6488354097176120060,
//                          "subject": "00ecd3ab-9af4-e711-906e-001560a04062",
//                          "not_before": "2020-07-22T16:39:55+0000",
//                          "not_after": "2021-07-22T16:39:55+0000",
//                          "attribute": [
//                              {
//                                  "attr_type": {
//                                      "id": "2.5.4.789.1"
//                                  },
//                                  "attribute_values": [
//                                      {
//                                          "objects": {
//                                              "name": "Location",
//                                              "value": "Vietnam"
//                                          }
//                                      }
//                                  ]
//                              },
//                              {
//                                  "attr_type": {
//                                      "id": "2.5.4.789.1"
//                                  },
//                                  "attribute_values": [
//                                      {
//                                          "objects": {
//                                              "name": "Company",
//                                              "value": "Intel"
//                                          }
//                                      }
//                                  ]
//                              }
//                          ],
//                          "fingerprint_sha384": "7149d2dde1b44f293515f14f80e554ae874c68bde18891e6020a00895f85efa70b4e7a762bbcbcfbf703a09efa2af5b4"
//                      }
//                  }
//              }
//          },
//          "signature": "Pauz4EN6RtpWuyyFZpI/S8cXia2qqAnbOmWLHzZzLEfx0D4D1zr/Soj35aN0BnngNUw4fxGcSv0oUrq5DNc0TrVf+/Doc/KcU74Iwm2+wR8MOzHAoOzW/LNlcpMOv13SabTjhJ6eQpcIoYz4XrqmMC+s3jiYnyhQ5PzFnd4K2BoJWT7hj5gvjXYX1Ccss/4Cunt3zkQsc5fnXf/ask9Gz4WqR6Qra5DQQsYKp0qdaKA4skKJVFWWDsrks+0HvXPkSLDa11xA9lq45YPJU9vPX0SMyu7txfeBeVEJ7Ov1kkE+H2ukOtiHwZZdkcuOh9h64D6q7qzTjRjjeOntgJjrooXRDsFE8SCpTh5clKLTaK+0mJCGsdcvbrBtH/UCNMHZWtB5/b+uaXeCbamOiN7oAgqI0I4ttcEonehn3HaXiwAgLbkrW1LgxWODGlUpogheCDMAjkOHyl2nwpeqjIq4n5WFfVo2NUQv5JnEJ2QZYNCEd+rOKIkCqgmoc9gCq6DM"
//      }
// ---
