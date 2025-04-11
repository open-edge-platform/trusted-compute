/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	"io/ioutil"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

//
// Provided the TagWriteRequest from, delete any existing tags, define/write
// tag to the TPM's nvram.  The receiving side of this equation is in 'quote.go'
// where the asset tag is used to hash the nonce and is also appended to the
// quote xml.
//
func SetAssetTag(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/asset_tag:SetAssetTag() Entering")
		defer log.Trace("controllers/asset_tag:SetAssetTag() Leaving")

		log.Debugf("controllers/asset_tag:SetAssetTag() Request: %s", httpRequest.URL.Path)

		var tagWriteRequest taModel.TagWriteRequest

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("controllers/asset_tag:setAssetTag( %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.WithError(err).Errorf("controllers/asset_tag:SetAssetTag() %s - Error reading request body for request: %s", message.AppRuntimeErr, httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error parsing request", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&tagWriteRequest)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/asset_tag:SetAssetTag() %s - Error marshaling json data: %s for request: %s", message.InvalidInputBadParam, string(data), httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusBadRequest}
		}

		err = requestHandler.DeployAssetTag(&tagWriteRequest)
		if err != nil {
			log.WithError(err).Errorf("controllers/asset_tag:SetAssetTag() %s - Error while deploying asset tag", message.AppRuntimeErr)
			return err
		}
		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
