/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	//	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func IsLinuxHost(hostInfo *model.HostInfo) bool {
	defaultLog.Trace("utils/host:IsLinuxHost() Entering")
	defer defaultLog.Trace("utils/host:IsLinuxHost() Leaving")

	osName := strings.ToUpper(strings.TrimSpace(hostInfo.OSName))
	// true when running on a linux host that is not a docker container
	if osName != model.OsWindows.String() && osName != model.OsWindows2k16.String() &&
		osName != model.OsWindows2k16dc.String() && osName != model.OsVMware.String() &&
		!hostInfo.IsDockerEnvironment {
		return true
	}
	return false
}

func GetDefaultSoftwareFlavorGroups(components []string) []string {
	defaultLog.Trace("utils/host:GetDefaultSoftwareFlavorGroups() Entering")
	defer defaultLog.Trace("utils/host:GetDefaultSoftwareFlavorGroups() Leaving")

	var fgNames []string
	for _, component := range components {
		if component == model.HostComponentTagent.String() {
			fgNames = append(fgNames, models.FlavorGroupsPlatformSoftware.String())
		} else if component == model.HostComponentWlagent.String() {
			fgNames = append(fgNames, models.FlavorGroupsWorkloadSoftware.String())
		}
	}
	return fgNames
}

func DetermineHostState(err error) hvs.HostState {
	defaultLog.Trace("utils/host:DetermineHostState() Entering")
	defer defaultLog.Trace("utils/host:DetermineHostState() Leaving")

	if strings.Contains(err.Error(), "connect") {
		if strings.Contains(err.Error(), "connection timed out") {
			defaultLog.Warnf("Failed connection to host, host has CONNECTION_TIMEOUT state with error message: %s", err.Error())
			return hvs.HostStateConnectionTimeout
		} else {
			defaultLog.Warnf("Failed connection to host, host has CONNECTION_FAILURE state with error message: %s", err.Error())
			return hvs.HostStateConnectionFailure
		}

	} else if strings.Contains(err.Error(), "net/http") {
		if strings.Contains(err.Error(), "TLS handshake timeout") {
			defaultLog.Warnf("Failed connection to host, host has CONNECTION_TIMEOUT state with error message: %s", err.Error())
			return hvs.HostStateConnectionTimeout
		} else {
			defaultLog.Warnf("Failed connection to host, host has CONNECTION_FAILURE state with error message: %s", err.Error())
			return hvs.HostStateConnectionFailure
		}

	} else if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "incorrect user name or password") {
		defaultLog.Warnf("Failed to get response from host, host has UNAUTHORIZED state with error message: %s", err.Error())
		return hvs.HostStateUnauthorized
	}

	defaultLog.Warnf("Failed to get response from host, host has UNKNOWN state with error message: %s", err.Error())
	return hvs.HostStateUnknown
}
