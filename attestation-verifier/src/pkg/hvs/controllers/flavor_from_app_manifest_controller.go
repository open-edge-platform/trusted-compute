/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/xml"
	"errors"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"net/http"
	"strings"
)

type FlavorFromAppManifestController struct {
	FlavorController FlavorController
}

func NewFlavorFromAppManifestController(fc FlavorController) *FlavorFromAppManifestController {
	return &FlavorFromAppManifestController{
		FlavorController: fc,
	}
}

func (controller FlavorFromAppManifestController) CreateSoftwareFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_from_app_manifest_controller:CreateSoftwareFlavor() Entering")
	defer defaultLog.Trace("controllers/flavor_from_app_manifest_controller:CreateSoftwareFlavor() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeXml {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Errorf("controllers/flavor_from_app_manifest_controller:CreateSoftwareFlavor() %s : The request body"+
			" is not provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var appManifestRequest *hvs.ManifestRequest
	dec := xml.NewDecoder(r.Body)
	err := dec.Decode(&appManifestRequest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Failed to decode request body as manifest request", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode XML request body"}
	}

	err = validateRequest(appManifestRequest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller: CreateSoftwareFlavor() "+
			"%s : %s", commLogMsg.InvalidInputBadParam, err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	//get connection string by host ID
	if appManifestRequest.ConnectionString == "" {
		connectionString, status, err := controller.getConnectionStringByHostId(appManifestRequest.HostId)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
				"CreateSoftwareFlavor() %s : Error getting connection string using host ID", commLogMsg.AppRuntimeErr)
			return nil, status, &commErr.ResourceError{Message: err.Error()}
		}
		appManifestRequest.ConnectionString = connectionString
	}

	appManifestRequest.ConnectionString, _, err = GenerateConnectionString(appManifestRequest.ConnectionString,
		controller.FlavorController.HostCon.HCConfig.Username,
		controller.FlavorController.HostCon.HCConfig.Password,
		controller.FlavorController.HostCon.HCStore)

	if err != nil {
		defaultLog.Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Error generating complete connection string with credentials", commLogMsg.AppRuntimeErr)
		return "", http.StatusInternalServerError, &commErr.ResourceError{Message: "Error generating complete " +
			"connection string with credentials"}
	}

	hcInstance, err := controller.FlavorController.HostCon.HCConfig.HostConnectorProvider.
		NewHostConnector(appManifestRequest.ConnectionString)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Failed to get host connector instance", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to get host connector instance"}
	}
	measurement, err := hcInstance.GetMeasurementFromManifest(appManifestRequest.Manifest)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Failed to get measurement from manifest", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to get measurement from manifest"}
	}

	measurementBytes, err := xml.Marshal(measurement)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Error marshalling measurement to string", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error marshalling measurement to string"}
	}
	softwareFlavorInstance := types.NewSoftwareFlavor(string(measurementBytes))
	softwareFlavor, err := softwareFlavorInstance.GetSoftwareFlavor()
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Error getting software flavor from measurement", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error getting software flavor from measurement"}
	}

	_, err = controller.FlavorController.createFlavors(models.FlavorCreateRequest{FlavorCollection: hvs.FlavorCollection{Flavors: []hvs.Flavors{{Flavor: *softwareFlavor}}}, FlavorgroupNames: appManifestRequest.FlavorGroupNames})
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_from_app_manifest_controller:"+
			"CreateSoftwareFlavor() %s : Error creating new SOFTWARE flavor", commLogMsg.AppRuntimeErr)
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor with same id/label already exists"}
		}
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error creating new SOFTWARE flavor"}
	}
	return softwareFlavor, http.StatusCreated, nil
}

func validateRequest(appManifestRequest *hvs.ManifestRequest) error {
	defaultLog.Trace("controllers/flavor_from_app_manifest_controller:validateRequest() Entering")
	defer defaultLog.Trace("controllers/flavor_from_app_manifest_controller:validateRequest() Leaving")

	if strings.TrimSpace(appManifestRequest.ConnectionString) == "" {
		if appManifestRequest.HostId == uuid.Nil {
			return errors.New("Either connection string or host Id must be provided")
		}
	} else {
		err := utils.ValidateConnectionString(appManifestRequest.ConnectionString)
		if err != nil {
			return err
		}
	}

	if strings.Contains(appManifestRequest.Manifest.Label, constants.DefaultSoftwareFlavorPrefix) ||
		strings.Contains(appManifestRequest.Manifest.Label, constants.DefaultWorkloadFlavorPrefix) {
		return errors.New("Default manifest cannot be provided for flavor creation")
	}
	return nil
}

func (controller FlavorFromAppManifestController) getConnectionStringByHostId(hostId uuid.UUID) (string, int, error) {
	defaultLog.Trace("controllers/flavor_from_app_manifest_controller:getConnectionStringByHostId() Entering")
	defer defaultLog.Trace("controllers/flavor_from_app_manifest_controller:getConnectionStringByHostId() Leaving")

	host, err := controller.FlavorController.HostCon.HStore.Retrieve(hostId, nil)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			return "", http.StatusBadRequest, errors.New("Host with given ID does not exist")
		} else {
			defaultLog.Errorf("controllers/flavor_from_app_manifest_controller:"+
				"getConnectionStringByHostId() %s : Error getting host info by host ID from host store", commLogMsg.AppRuntimeErr)
			return "", http.StatusInternalServerError, errors.New("Error getting host info by host ID from host store")
		}
	}
	return host.ConnectionString, http.StatusOK, nil
}
