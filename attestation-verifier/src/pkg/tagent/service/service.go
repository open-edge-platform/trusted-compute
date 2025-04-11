/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
	"strings"
)

type TrustAgentService interface {
	Start() error
	Stop() error
}

type NatsParameters struct {
	config.NatsService
	CredentialFile    string
	TrustedCaCertsDir string
}

type WebParameters struct {
	commConfig.ServerConfig
	TLSCertFilePath           string
	TLSKeyFilePath            string
	TrustedJWTSigningCertsDir string
	TrustedCaCertsDir         string
}

type ServiceParameters struct {
	Mode           string
	Web            WebParameters
	Nats           NatsParameters
	RequestHandler common.RequestHandler
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewTrustAgentService(parameters *ServiceParameters) (TrustAgentService, error) {

	var service TrustAgentService
	var err error

	if strings.ToLower(parameters.Mode) == constants.CommunicationModeOutbound {

		service, err = newOutboundService(&parameters.Nats, parameters.RequestHandler, constants.PlatformInfoFilePath)
		if err != nil {
			return nil, errors.Wrapf(err, "Error creating the HVS subscriber")
		}

		if service == nil {
			return nil, errors.Wrapf(err, "Error: could not initialize hvs subscriber")
		}

	} else if parameters.Mode == "" || strings.ToLower(parameters.Mode) == constants.CommunicationModeHttp {

		// create and start webservice
		service, err = newWebService(&parameters.Web, parameters.RequestHandler, constants.HttpLogFile)
		if err != nil {
			return nil, errors.Wrapf(err, "Error while creating trustagent service")
		}

	} else {
		return nil, errors.Errorf("Unknown communication mode %s", parameters.Mode)
	}

	return service, nil
}
