/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"fmt"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type RequestHandler interface {
	GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest, aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error)
	GetHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error)
	GetAikDerBytes(aikCertPath string) ([]byte, error)
	DeployAssetTag(*taModel.TagWriteRequest) error
	GetBindingCertificateDerBytes(bindingKeyCertificatePath string) ([]byte, error)
	DeploySoftwareManifest(manifest *taModel.Manifest, varDir string) error
	GetApplicationMeasurement(manifest *taModel.Manifest, tBootXmMeasurePath string, logDirPath string) (*taModel.Measurement, error)
}

func NewRequestHandler(cfg *config.TrustAgentConfiguration) RequestHandler {
	return &requestHandlerImpl{
		cfg: cfg,
	}
}

type requestHandlerImpl struct {
	cfg *config.TrustAgentConfiguration
}

type EndpointError struct {
	Message    string
	StatusCode int
}

func (e EndpointError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
