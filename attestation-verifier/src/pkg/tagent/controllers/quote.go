/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"

	"io/ioutil"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func GetTpmQuote(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/quote:GetTpmQuote() Entering")
		defer log.Trace("controllers/quote:GetTpmQuote() Leaving")

		log.Debugf("controllers/quote:GetTpmQuote() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("controllers/quote:GetTpmQuote() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		var tpmQuoteRequest taModel.TpmQuoteRequest

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("controllers/quote:GetTpmQuote() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error reading request body", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&tpmQuoteRequest)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/quote:GetTpmQuote() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return &common.EndpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}

		}

		tpmQuoteResponse, err := requestHandler.GetTpmQuote(&tpmQuoteRequest, constants.AikCert, constants.MeasureLogFilePath, constants.RamfsDir)
		if err != nil {
			log.WithError(err).Errorf("controllers/quote:GetTpmQuote() %s - There was an error collecting the tpm quote", message.AppRuntimeErr)
			return &common.EndpointError{Message: "There was an error collecting the tpm quote", StatusCode: http.StatusInternalServerError}
		}

		xmlOutput, err := xml.MarshalIndent(tpmQuoteResponse, "  ", "    ")
		if err != nil {
			log.WithError(err).Errorf("controllers/quote:GetTpmQuote() %s - There was an error serializing the tpm quote", message.AppRuntimeErr)
			return &common.EndpointError{Message: "There was an error serializing the tpm quote", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/xml")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(xmlOutput).WriteTo(httpWriter)
		return nil
	}
}
