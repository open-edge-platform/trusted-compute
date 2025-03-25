// Host Verification Service
//
// The Host Verification Service (HVS) is a component responsible for generating and maintaining accurate trust
// evaluations for data center servers. The HVS provides an interface for defining acceptable passlisted policies (flavors)
// for data center servers. These flavor policies incorporate server firmware measurements, hardware capabilities,
// security technology information and additional configuration. The measured data and configuration injected into the
// HVS flavor policies incorporate chain of trust technology requirements for platform attestation.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 2
//  Host: hvs.com:8443
//  BasePath: /hvs/v2/
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package hvs
