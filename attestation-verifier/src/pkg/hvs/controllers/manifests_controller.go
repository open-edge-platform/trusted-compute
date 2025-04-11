/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	dm "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/util"
)

type ManifestsController struct {
	FlavorStore domain.FlavorStore
}

func NewManifestsController(fs domain.FlavorStore) *ManifestsController {
	return &ManifestsController{
		FlavorStore: fs,
	}
}

func (controller ManifestsController) GetManifest(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/manifests_controller:GetManifest() Entering")
	defer defaultLog.Trace("controllers/manifests_controller:GetManifest() Leaving")

	ids := r.URL.Query()["id"]
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	filterCriteria, err := validateFlavorFilterCriteria(key, value, "", ids, nil, "", "")
	if err != nil {
		secLog.Errorf("controllers/manifests_controller:GetManifest()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavors, err := controller.FlavorStore.Search(&dm.FlavorVerificationFC{
		FlavorFC: *filterCriteria,
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Failed to search flavor from store", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search flavor from store"}
	}

	if signedFlavors == nil || len(signedFlavors) == 0 {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Flavor with given details does not exist", commLogMsg.InvalidInputBadParam)
		return "", http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given details does not exist"}
	}

	var fmc util.FlavorToManifestConverter
	if signedFlavors[0].Flavor.Meta.Description[hvs.FlavorPartDescription].(string) == string(hvs.FlavorPartSoftware) {
		manifest := fmc.GetManifestFromFlavor(signedFlavors[0].Flavor)
		return manifest, http.StatusOK, nil
	} else {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Flavor associated with the provided id is not a SOFTWARE flavor", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor associated with the provided id is not " +
			"a SOFTWARE flavor"}
	}
}
