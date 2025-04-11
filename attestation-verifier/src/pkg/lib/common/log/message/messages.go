/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package message

var (
	InvalidInputProtocolViolation = "input validation failed: protocol violation"
	InvalidInputBadEncoding       = "input validation failed: unacceptable encodings"
	InvalidInputBadParam          = "input validation failed: invalid parameter names"
	OutputFailed                  = "failed to generate output"

	TLSConnectFailed = "backend TLS connection failed"

	AuthenticationSuccess = "user authenticated"
	AuthenticationFailed  = "user authentication failed"
	AuthorizedAccess      = "authorized request"
	UnauthorizedAccess    = "unauthorized request"

	AppRuntimeErr      = "application errors and system events: syntax and runtime errors"
	BadConnection      = "application errors and system events: connectivity problems"
	PerformanceProblem = "application errors and system events: performance issues"

	ConfigChanged = "application errors and system events: config changed"
	ServiceStart  = "service start"
	ServiceStop   = "service stop"
	LogInit       = "log init"

	UserAdded         = "user added"
	UserDeleted       = "user deleted"
	PrivilegeModified = "privilege modified"
	TokenIssued       = "token generated for user"
	TokenModified     = "token modified"
	SU                = "using systems administrative privileges"

	EncKeyUsed = "using data encrypting keys"
	DataImport = "data imported"
	DataExport = "data exported"
)
