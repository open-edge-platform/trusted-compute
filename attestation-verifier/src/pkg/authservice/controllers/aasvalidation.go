/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"errors"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"regexp"
)

var (
	roleNameReg    = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,40}$`)
	serviceNameReg = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,20}$`)
	contextReg     = regexp.MustCompile(`^[A-Za-z0-9-_/.@,=;: *]{0,512}$`)
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

// ValidateRoleString is used to check if the string is a valid AAS role string
func ValidateRoleString(roleString string) error {
	if !roleNameReg.MatchString(roleString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid role string provided")
	}

	return nil
}

// ValidateServiceString is used to check if the string is a valid AAS service string
func ValidateServiceString(serviceString string) error {
	if !serviceNameReg.MatchString(serviceString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid service string provided")
	}

	return nil
}

// ValidateContextString is used to check if the string is a valid AAS context string
func ValidateContextString(contextString string) error {
	if !contextReg.MatchString(contextString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid context string provided")
	}

	return nil
}

// ValidatePermissions is used to check if the string is a valid AAS context string
func ValidatePermissions(permissions []string) error {

	for i := range permissions {
		if len(permissions[i]) > 512 {
			secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
			return errors.New("Invalid Permissions string provided. Max 512 charecters allowed per permission")
		}
	}

	return nil
}
