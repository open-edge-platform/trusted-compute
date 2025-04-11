/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	"net"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

func GetCurrentIP() (net.IP, error) {

	currentIP := os.Getenv(constants.EnvCurrentIP)
	if currentIP == "" {
		return nil, errors.New(constants.EnvCurrentIP + " is not define in the environment")
	}

	ip := net.ParseIP(currentIP)
	if ip == nil {
		return nil, errors.Errorf("Could not parse ip address '%s'", currentIP)
	}

	return ip, nil
}

func GetConnectionString(connType string, hostname string, port int) string {
	log.Trace("util/connection_string:GetConnectionString() Entering")
	defer log.Trace("util/connection_string:GetConnectionString() Leaving")

	switch connType {
	case constants.CommunicationModeHttp:
		return fmt.Sprintf("intel:https://%s:%d", hostname, port)
	case constants.CommunicationModeOutbound:
		return fmt.Sprintf("intel:nats://%s", hostname)
	default:
		return ""
	}
}
