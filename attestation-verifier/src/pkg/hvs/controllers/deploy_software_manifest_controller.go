/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type DeploySoftwareManifestController struct {
	FlavorStore domain.FlavorStore
	HController HostController
}

func NewDeploySoftwareManifestController(fs domain.FlavorStore, hc HostController) *DeploySoftwareManifestController {
	return &DeploySoftwareManifestController{
		FlavorStore: fs,
		HController: hc,
	}
}

func (controller *DeploySoftwareManifestController) DeployManifest(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/deploy_software_manifest_controller:DeployManifest() Entering")
	defer defaultLog.Trace("controllers/deploy_software_manifest_controller:DeployManifest() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Errorf("controllers/deploy_software_manifest_controller:DeployManifest() %s : The request body"+
			" is not provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqDeployManifest *hvs.DeployManifestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqDeployManifest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/deploy_software_manifest_controller:"+
			"DeployManifest() %s : Failed to decode request body as deploy manifest request", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode request body"}
	}

	err = validateDeployManifestRequest(reqDeployManifest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/deploy_software_manifest_controller:"+
			"DeployManifest() %s : Invalid deploy manifest request provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavor, err := controller.FlavorStore.Retrieve(reqDeployManifest.FlavorId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", reqDeployManifest.FlavorId).Info(
				"controllers/deploy_software_manifest_controller:DeployManifest() Flavor with given ID does not exist")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			defaultLog.WithError(err).Errorf("controllers/deploy_software_manifest_controller:"+
				"DeployManifest() %s : Failed to retrieve flavor from store", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve flavor from store"}
		}
	}

	if signedFlavor.Flavor.Meta.Description[hvs.FlavorPartDescription].(string) != string(hvs.FlavorPartSoftware) {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor associated with the provided flavor " +
			"id is not a SOFTWARE flavor"}
	}

	var fmc util.FlavorToManifestConverter
	manifest := fmc.GetManifestFromFlavor(signedFlavor.Flavor)

	httpStatus, err := controller.deployManifestToHost(reqDeployManifest.HostId, manifest)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/deploy_software_manifest_controller:"+
			"DeployManifest() %s : Failed to deploy manifest to host", commLogMsg.AppRuntimeErr)
		return nil, httpStatus, &commErr.ResourceError{Message: "Failed to deploy manifest to host"}
	}
	return nil, httpStatus, nil
}

func (controller *DeploySoftwareManifestController) deployManifestToHost(hostId uuid.UUID, manifest model.Manifest) (int, error) {
	defaultLog.Trace("controllers/deploy_software_manifest_controller:deployManifestToHost() Entering")
	defer defaultLog.Trace("controllers/deploy_software_manifest_controller:deployManifestToHost() Leaving")

	host, err := controller.HController.HStore.Retrieve(hostId, nil)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			return http.StatusBadRequest, &commErr.ResourceError{Message: "Host with given ID does not exist"}
		} else {
			return http.StatusInternalServerError, errors.Wrap(err, "Failed to retrieve host from store")
		}
	}

	connectionString, _, err := GenerateConnectionString(host.ConnectionString,
		controller.HController.HCConfig.Username,
		controller.HController.HCConfig.Password,
		controller.HController.HCStore)

	hconnector, err := controller.HController.HCConfig.HostConnectorProvider.NewHostConnector(connectionString)
	if err != nil {
		return http.StatusInternalServerError, errors.Wrap(err, "Could not instantiate host connector")
	}

	err = hconnector.DeploySoftwareManifest(manifest)
	if err != nil {
		return http.StatusInternalServerError, errors.Wrap(err, "Error deploying manifest to host")
	}
	return http.StatusOK, nil
}

func validateDeployManifestRequest(reqDeployManifest *hvs.DeployManifestRequest) error {
	defaultLog.Trace("controllers/deploy_software_manifest_controller:validateDeployManifestRequest() Entering")
	defer defaultLog.Trace("controllers/deploy_software_manifest_controller:validateDeployManifestRequest() Leaving")

	if reqDeployManifest.HostId == uuid.Nil {
		return errors.New("Invalid Host Id provided in request")
	} else if reqDeployManifest.FlavorId == uuid.Nil {
		return errors.New("Invalid Flavor Id provided in request")
	}

	return nil
}
