/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"

	"io/ioutil"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
)

// Writes the manifest xml received to /opt/trustagent/var/manifest_{UUID}.xml.
func DeployManifest(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/deploy_manifest:DeployManifest() Entering")
		defer log.Trace("controllers/deploy_manifest:DeployManifest() Leaving")

		log.Debugf("controllers/deploy_manifest:DeployManifest() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/xml" {
			log.Errorf("controllers/deploy_manifest:DeployManifest() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.WithError(err).Errorf("controllers/deploy_manifest:DeployManifest() Error reading manifest xml")
			return &common.EndpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}
		}

		// make sure the xml is well formed
		manifest := taModel.Manifest{}
		err = xml.Unmarshal(manifestXml, &manifest)
		if err != nil {
			secLog.WithError(err).Error("controllers/deploy_manifest:DeployManifest() Invalid xml format")
			return &common.EndpointError{Message: "Error: Invalid xml format", StatusCode: http.StatusBadRequest}
		}

		err = requestHandler.DeploySoftwareManifest(&manifest, constants.VarDir)
		if err != nil {
			log.WithError(err).Errorf("controllers/deploy_manifest:DeployManifest() %s - Error while deploying manifest", message.AppRuntimeErr)
			return err
		}

		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
