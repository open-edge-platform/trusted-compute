/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package cms

//
// swagger:operation GET /version Version GetVersion
// ---
// description: |
//   GetVersion is used to get the version of the application.
//   Returns - The version of the application.
//
// produces:
//   - text/plain
// responses:
//   '200':
//     description: Successfully retrieved the version.
//     content: text/plain
//
// x-sample-call-endpoint: https://cms.com:8445/cms/v1/version
// x-sample-call-output: |
//   Service Name: Certificate Management Service
//   Version: v3.4.0-0f0162ea
//   Build Date: 2021-03-08T12:31:46+0000
