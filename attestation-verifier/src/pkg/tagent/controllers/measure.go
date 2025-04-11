/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"

	"io/ioutil"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

// Uses /opt/tbootxml/bin/measure to measure the supplied manifest
func GetApplicationMeasurement(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/measure:GetApplicationMeasurement() Entering")
		defer log.Trace("controllers/measure:GetApplicationMeasurement() Leaving")

		log.Debugf("controllers/measure:GetApplicationMeasurement() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/xml" {
			log.Errorf("controllers/measure:GetApplicationMeasurement() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/measure:GetApplicationMeasurement() %s - Error reading manifest xml", message.InvalidInputBadParam)
			return &common.EndpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}
		}

		// make sure the xml is well formed, all other validation will be
		// peformed by 'measure' cmd line below
		manifest := taModel.Manifest{}
		err = xml.Unmarshal(manifestXml, &manifest)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/measure:GetApplicationMeasurement() %s - Invalid xml format", message.InvalidInputBadParam)
			return &common.EndpointError{Message: "Error: Invalid XML format", StatusCode: http.StatusBadRequest}
		}

		measurement, err := requestHandler.GetApplicationMeasurement(&manifest, constants.TBootXmMeasurePath, constants.LogDir)
		if err != nil {
			log.WithError(err).Errorf("controllers/measure:GetApplicationMeasurement() %s - Error getting measurement", message.AppRuntimeErr)
			return err
		}

		measureBytes, err := xml.Marshal(measurement)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/measure:GetApplicationMeasurement() %s - Invalid xml format", message.InvalidInputBadParam)
			return &common.EndpointError{Message: "Error: Invalid XML format of generated XML", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(measureBytes).WriteTo(httpWriter)
		return nil
	}
}
