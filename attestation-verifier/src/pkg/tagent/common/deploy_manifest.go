/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	flavorConsts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func (handler *requestHandlerImpl) DeploySoftwareManifest(manifest *taModel.Manifest, varDir string) error {

	manifestXml, err := xml.Marshal(manifest)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Failed to marshal manifest %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Failed to marshal manifest", StatusCode: http.StatusBadRequest}
	}

	err = validation.ValidateUUIDv4(manifest.Uuid)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Invalid uuid %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Invalid uuid", StatusCode: http.StatusBadRequest}
	}

	if len(manifest.Label) == 0 {
		log.Error("The manifest did not contain a label")
		return &EndpointError{Message: "Error: The manifest did not contain a label", StatusCode: http.StatusBadRequest}
	}

	var manifestlabels []string
	manifestlabels = append(manifestlabels, manifest.Label)
	err = validation.ValidateStrings(manifestlabels)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Invalid manifest labels %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Invalid manifest labels", StatusCode: http.StatusBadRequest}
	}

	if strings.Contains(manifest.Label, flavorConsts.DefaultSoftwareFlavorPrefix) ||
		strings.Contains(manifest.Label, flavorConsts.DefaultWorkloadFlavorPrefix) {
		log.Errorf("common/deploy_manifest:DeploySoftwareManifest() Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		return &EndpointError{Message: " Default flavor's manifest (%s) is part of installation", StatusCode: http.StatusBadRequest}
	}

	// establish the name of the manifest file and write the file
	manifestFile := path.Join(varDir, "manifest_"+manifest.Uuid+".xml")
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		log.Errorf("common/deploy_manifest:DeploySoftwareManifest() Could not write manifest: %s", err)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return nil
}
