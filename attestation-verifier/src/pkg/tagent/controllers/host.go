/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"

	"encoding/json"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

func GetPlatformInfo(requestHandler common.RequestHandler, platformInfoFilePath string) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/host:GetPlatformInfo() Entering")
		defer log.Trace("controllers/host:GetPlatformInfo() Leaving")

		log.Debugf("controllers/host:GetPlatformInfo() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type when calling /host
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("controllers/host:GetPlatformInfo() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		hostInfo, err := requestHandler.GetHostInfo(platformInfoFilePath)
		if err != nil {
			log.WithError(err).Errorf("controllers/host:GetPlatformInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		hostInfoJSON, err := json.Marshal(hostInfo)
		if err != nil {
			log.Errorf("controllers/host:GetPlatformInfo() %s - There was an error marshaling host-info %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(hostInfoJSON).WriteTo(httpWriter)
		return nil
	}
}
