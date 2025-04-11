/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

// these are un-used constants,
// remove this file to get rid of them
const (
	BearerTokenEnv        = "BEARER_TOKEN"
	CmsBaseUrlEnv         = "CMS_BASE_URL"
	AasApiUrlEnv          = "AAS_API_URL"
	HvsServiceUsernameEnv = "HVS_SERVICE_USERNAME"
	HvsServicePasswordEnv = "HVS_SERVICE_PASSWORD"
	CmsTlsCertDigestEnv   = "CMS_TLS_CERT_SHA384"

	// this is ok to be in constants package
	// but the name is unclear of what SSL cert...
	// moved to tasks/database.go since it is only used there
	DefaultSSLCertFilePath = ConfigDir + "hvsdbsslcert.pem"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
