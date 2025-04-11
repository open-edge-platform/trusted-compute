/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

// Returns the WLA provisioned binding key certificate from /etc/workload-agent/bindingkey.pem
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/binding-key-certificate -k --noproxy "*"
func GetBindingKeyCertificate(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/binding_key_certificate:GetBindingKeyCertificate() Entering")
		defer log.Trace("controllers/binding_key_certificate:GetBindingKeyCertificate() Leaving")

		log.Debugf("controllers/binding_key_certificate:GetBindingKeyCertificate() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type, exlude other values
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("controllers/binding_key_certificate:GetBindingKeyCertificate() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		bindingKeyBytes, err := requestHandler.GetBindingCertificateDerBytes(constants.BindingKeyCertificatePath)
		if err != nil {
			log.WithError(err).Errorf("controllers/binding_key_certificate:GetBindingKeyCertificate() %s - Error while getting binding key", message.AppRuntimeErr)
			return err
		}

		httpWriter.Header().Set("Content-Type", "application/x-pem-file")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
		return nil
	}
}
