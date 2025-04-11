/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strconv"
	"strings"
)

type FlavorgroupController struct {
	FlavorGroupStore    domain.FlavorGroupStore
	FlavorTemplateStore domain.FlavorTemplateStore
	FlavorStore         domain.FlavorStore
	HostStore           domain.HostStore
	HTManager           domain.HostTrustManager
}

var flavorGroupSearchParams = map[string]bool{"id": true, "nameEqualTo": true, "nameContains": true, "includeFlavorContent": true, "limit": true, "afterId": true}

func (controller FlavorgroupController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavorgroup_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqFlavorGroup hvs.FlavorGroup
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqFlavorGroup)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavorgroup_controller:Create() %s :  Failed to decode request body as FlavorGroup", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := controller.ValidateFlavorGroup(reqFlavorGroup); err != nil {
		secLog.WithError(err).Errorf("controllers/flavorgroup_controller:Create() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid flavorgroup data "}
	}

	existingFlavorGroups, err := controller.FlavorGroupStore.Search(&models.FlavorGroupFilterCriteria{
		NameEqualTo: reqFlavorGroup.Name,
	})
	if existingFlavorGroups != nil && len(existingFlavorGroups) > 0 {
		secLog.WithField("Name", existingFlavorGroups[0].Name).Warningf("%s: Trying to create duplicated FlavorGroup from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "FlavorGroup with same name already exist"}
	}

	// Persistence
	newFlavorGroup, err := controller.FlavorGroupStore.Create(&reqFlavorGroup)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavorgroup_controller:Create() Flavorgroup save failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Error while inserting a new Flavorgroup")
	}

	secLog.WithField("Name", reqFlavorGroup.Name).Infof("%s: FlavorGroup created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newFlavorGroup, http.StatusCreated, nil
}

func (controller FlavorgroupController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavorgroups")

	if err := utils.ValidateQueryParams(r.URL.Query(), flavorGroupSearchParams); err != nil {
		secLog.Errorf("controllers/flavorgroup_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	id := r.URL.Query().Get("id")
	nameEqualTo := r.URL.Query().Get("nameEqualTo")
	nameContains := r.URL.Query().Get("nameContains")
	limit := r.URL.Query().Get("limit")
	afterId := r.URL.Query().Get("afterId")

	includeFlavorContent, err := strconv.ParseBool(r.URL.Query().Get("includeFlavorContent"))
	if err != nil {
		includeFlavorContent = false
	}

	filter, err := ValidateFgCriteria(id, nameEqualTo, nameContains, limit, afterId)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavorgroup_controller:Search()  %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria"}
	}

	flavorgroups, err := controller.FlavorGroupStore.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavorgroup_controller:Search() Flavorgroup get all failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search Flavorgroups"}
	}

	flavorgroupCollection, err := controller.getAssociatedFlavorAndTemplates(flavorgroups, includeFlavorContent, *filter)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavorgroup_controller:Search() Error getting flavor(s) " +
			"associated with flavor group")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search Flavorgroups"}
	}

	secLog.Infof("%s: Return flavorgroup query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorgroupCollection, http.StatusOK, nil
}

func (controller FlavorgroupController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delFlavorGroup, err := controller.FlavorGroupStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Delete()  FlavorGroup with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Delete() attempt to delete invalid FlavorGroup")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete FlavorGroup"}
		}
	}

	if models.IsDefaultFlavorgroup(delFlavorGroup.Name) {
		secLog.Error("controllers/flavorgroup_controller:Delete() attempt to delete default FlavorGroup")
		errorMsg := delFlavorGroup.Name + " is a system generated default flavorgroup which is protected and cannot be deleted"
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: errorMsg}
	}

	hostsExist, err := controller.FlavorGroupStore.HasAssociatedHosts(id)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() failed to get hosts associated with FlavorGroup")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete FlavorGroup"}
	}
	if hostsExist {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() one or more than one hosts are still linked with FlavorGroup")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to delete FlavorGroup, " +
			"one or more than one hosts are still linked with FlavorGroup"}
	}

	if err := controller.FlavorGroupStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() failed to delete FlavorGroup")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete FlavorGroup"}
	}
	secLog.WithField("user", delFlavorGroup.Name).Infof("FlavorGroup deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller FlavorgroupController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	flavorGroup, err := controller.FlavorGroupStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Retrieve() FlavorGroup with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Retrieve() failed to retrieve FlavorGroup")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorGroup"}
		}
	}

	//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
	return flavorGroup, http.StatusOK, nil
}

func (controller FlavorgroupController) ValidateFlavorGroup(flavorGroup hvs.FlavorGroup) error {
	defaultLog.Trace("controllers/flavorgroup_controller:ValidateFlavorGroup() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:ValidateFlavorGroup() Leaving")

	if flavorGroup.Name == "" {
		return errors.New("FlavorGroup Name must be specified")
	}
	if flavorGroup.Name != "" {
		if errs := validation.ValidateStrings([]string{flavorGroup.Name}); errs != nil {
			return errors.Wrap(errs, "Valid FlavorGroup Name must be specified")
		}
	}
	if flavorGroup.FlavorTemplateIds != nil && len(flavorGroup.FlavorTemplateIds) > 0 {
		for _, templateId := range flavorGroup.FlavorTemplateIds {
			if errs := validation.ValidateUUIDv4(templateId.String()); errs != nil {
				return errors.Wrap(errs, "Valid Flavor Template ID must be specified")
			}

			_, err := controller.FlavorTemplateStore.Retrieve(templateId, false)
			if err != nil {
				switch err.(type) {
				case *commErr.StatusNotFoundError:
					return errors.Wrap(err, "Flavor template with given ID does not exist or has been deleted")
				default:
					return errors.Wrap(err, "Failed to retrieve FlavorTemplate with the given ID")
				}
			}

		}
	}

	if len(flavorGroup.MatchPolicies) == 0 {
		return errors.New("Flavor Type Match Policy Collection must be specified")
	}
	return nil
}

func ValidateFgCriteria(id string, nameEqualTo string, nameContains string, limitString string, afterIdString string) (*models.FlavorGroupFilterCriteria, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:ValidateFgCriteria() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:ValidateFgCriteria() Leaving")

	filter := models.FlavorGroupFilterCriteria{}

	if id != "" {
		flavorgroupId, err := uuid.Parse(id)
		if err != nil {
			secLog.WithError(err).Error("controllers/flavorgroup_controller:Search() Invalid id query param value, must be UUID")
			return nil, errors.New("Invalid id query param value, must be UUID")
		}
		filter.Ids = []uuid.UUID{flavorgroupId}
	}

	if nameEqualTo != "" {
		if errs := validation.ValidateStrings([]string{nameEqualTo}); errs != nil {
			return nil, errors.Wrap(errs, "Valid contents for NameEqualTo must be specified")
		}
		filter.NameEqualTo = nameEqualTo
	}
	if nameContains != "" {
		if errs := validation.ValidateStrings([]string{nameContains}); errs != nil {
			return nil, errors.Wrap(errs, "Valid contents for NameContains must be specified")
		}
		filter.NameContains = nameContains
	}

	limit, afterId, err := validation.ValidatePaginationValues(limitString, afterIdString)
	if err != nil {
		return nil, err
	}
	filter.Limit = limit
	filter.AfterId = afterId

	return &filter, nil
}

// AddFlavor creates the FlavorGroupFlavor link in the FlavorGroupStore
func (controller FlavorgroupController) AddFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:AddFlavor() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:AddFlavor() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavorgroup_controller:AddFlavor() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	// Get the Flavor ID from the POST body
	var linkRequest hvs.FlavorgroupFlavorLinkCriteria
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&linkRequest)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  Failed to decode request body as FlavorgroupFlavorLinkCriteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	// Get the FlavorGroup ID from the URL
	fgID := uuid.MustParse(mux.Vars(r)["fgID"])

	// check if FlavorGroup exists
	_, err = controller.FlavorGroupStore.Retrieve(fgID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s : FlavorGroup %s does not exist", commLogMsg.AppRuntimeErr, fgID)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup does not exist"}
		} else {
			defaultLog.WithError(err).WithField("flavorGroup", fgID).Errorf("controllers/flavorgroup_controller:AddFlavor() %s : Error retrieving FlavorGroup", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to create FlavorGroup-Flavor link"}
		}
	}

	// check for validity of flavorId in request
	if linkRequest.FlavorID == uuid.Nil {
		defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  Invalid Flavor ID %s in request body", commLogMsg.AppRuntimeErr, linkRequest.FlavorID)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid FlavorID in request"}
	}

	// check if Flavor exists
	_, err = controller.FlavorStore.Retrieve(linkRequest.FlavorID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  Flavor %s does not exist", commLogMsg.AppRuntimeErr, linkRequest.FlavorID)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor does not exist"}
		} else {
			defaultLog.WithError(err).WithField("flavor", linkRequest.FlavorID).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  Error checking for flavors", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while inserting a new Flavorgroup-Flavor link"}
		}
	}

	// now check if there is already a link between Flavor and FlavorGroup
	fgfl, err := controller.FlavorGroupStore.RetrieveFlavor(fgID, linkRequest.FlavorID)
	if err != nil {
		if !strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithField("flavorGroup", fgID).WithField("flavor", linkRequest.FlavorID).WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  Failed to fetch linked flavors for FlavorGroup", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while inserting a new Flavorgroup-Flavor link"}
		}
	}

	if fgfl != nil {
		defaultLog.WithField("flavorGroup", fgID).WithField("flavor", linkRequest.FlavorID).WithError(err).Errorf("controllers/flavorgroup_controller:AddFlavor() %s :  FlavorGroup-Flavor link already exists", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "FlavorGroup-Flavor link already exists"}
	}

	// Persistence
	links, err := controller.FlavorGroupStore.AddFlavors(fgID, []uuid.UUID{linkRequest.FlavorID})
	if err != nil {
		defaultLog.WithError(err).WithField("flavorGroup", fgID).WithField("flavor", linkRequest.FlavorID).Errorf("controllers/flavorgroup_controller:AddFlavor() %s : Flavorgroup-Flavor save failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("Error while inserting a new Flavorgroup-Flavor link")
	}

	// Add the affected Hosts to the Flavor Verify queue
	linkedHosts, err := controller.FlavorGroupStore.SearchHostsByFlavorGroup(fgID)
	if err != nil {
		defaultLog.WithError(err).WithField("flavorGroup", fgID).WithField("flavor", linkRequest.FlavorID).Errorf("controllers/flavorgroup_controller:AddFlavor() %s : Failed to fetch hosts linked to FlavorGroup", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("Error while inserting a new Flavorgroup-Flavor link")
	}

	// Since the host has been updated, add it to the verify queue
	err = controller.HTManager.VerifyHostsAsync(linkedHosts, false, false)
	if err != nil {
		defaultLog.WithError(err).WithField("linkedHosts", linkedHosts).Error("controllers/host_controller:AddFlavor() Addition of Host to Flavor Verify Queue failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while inserting a new Flavorgroup-Flavor link"}
	}

	defaultLog.WithField("linkedHosts", linkedHosts).Info("controllers/host_controller:AddFlavor() Added Host to Flavor Verify Queue")

	var newLink *hvs.FlavorgroupFlavorLink
	if links != nil {
		newLink = &hvs.FlavorgroupFlavorLink{
			FlavorGroupID: fgID,
			FlavorID:      links[0],
		}
	}

	secLog.WithField("flavorGroup", fgID).WithField("flavor", linkRequest.FlavorID).Infof("%s: Flavor-FlavorGroup link created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newLink, http.StatusCreated, nil
}

// RemoveFlavor deletes the FlavorGroupFlavor link in the FlavorGroupStore
func (controller FlavorgroupController) RemoveFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:RemoveFlavor() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:RemoveFlavor() Leaving")

	// Get the FlavorGroup, Flavor ID from the URL
	fgID := uuid.MustParse(mux.Vars(r)["fgID"])
	fID := uuid.MustParse(mux.Vars(r)["fID"])

	// check if link exists
	_, err := controller.FlavorGroupStore.RetrieveFlavor(fgID, fID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("flavorGroup", fID).WithField("flavor", fID).WithError(err).Errorf("controllers/flavorgroup_controller:RemoveFlavor() %s : FlavorGroup-Flavor link %s does not exist", commLogMsg.AppRuntimeErr, fgID)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup-Flavor link does not exist"}
		} else {
			defaultLog.WithError(err).WithField("flavorGroup", fID).WithField("flavor", fID).Errorf("controllers/flavorgroup_controller:RemoveFlavor() %s :  Error checking for FlavorGroup-Flavor links", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to remove FlavorGroup-Flavor link"}
		}
	}

	// remove flavor links
	err = controller.FlavorGroupStore.RemoveFlavors(fgID, []uuid.UUID{fID})
	if err != nil {
		defaultLog.WithField("flavorGroup", fID).WithField("flavor", fID).WithError(err).Errorf("controllers/flavorgroup_controller:RemoveFlavor() %s :  Error removing linked flavors ", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while removing Flavorgroup-Flavor links"}
	}

	// Add the affected Hosts to the Flavor Verify queue
	linkedHosts, err := controller.FlavorGroupStore.SearchHostsByFlavorGroup(fgID)
	if err != nil {
		defaultLog.WithError(err).WithField("flavorGroup", fgID).WithField("flavor", fID).Errorf("controllers/flavorgroup_controller:RemoveFlavor() %s : Failed to fetch hosts linked to FlavorGroup", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while removing Flavorgroup-Flavor links"}
	}

	// Since the host has been updated, add it to the verify queue
	err = controller.HTManager.VerifyHostsAsync(linkedHosts, false, false)
	if err != nil {
		defaultLog.WithError(err).WithField("linkedHosts", linkedHosts).Error("controllers/host_controller:RemoveFlavor() Addition of Host to Flavor Verify Queue failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while removing Flavorgroup-Flavor links"}
	}

	defaultLog.WithField("linkedHosts", linkedHosts).Info("controllers/host_controller:RemoveFlavor() Added Host to Flavor Verify Queue")

	secLog.WithField("flavorGroup", fID).WithField("flavor", fID).Infof("%s: Flavor-FlavorGroup link deleted by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

// SearchFlavors returns a list of Flavors linked to a particular FlavorGroup
func (controller FlavorgroupController) SearchFlavors(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:SearchFlavors() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:SearchFlavors() Leaving")

	// Get the FlavorGroup, Flavor ID from the URL
	fgID := uuid.MustParse(mux.Vars(r)["fgID"])

	// initialize so empty list is sent in response
	searchResults := []hvs.FlavorgroupFlavorLink{}

	// check if FlavorGroup exists
	_, err := controller.FlavorGroupStore.Retrieve(fgID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithField("flavorGroup", fgID).WithField("flavorGroup", fgID).WithError(err).Errorf("controllers/flavorgroup_controller:SearchFlavor() %s :  FlavorGroup not found ", commLogMsg.AppRuntimeErr)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup does not exist"}
		} else {
			defaultLog.WithField("flavorGroup", fgID).WithField("flavorGroup", fgID).WithError(err).Errorf("controllers/flavorgroup_controller:SearchFlavor() %s :  Error removing linked flavors ", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while searching FlavorGroups"}
		}
	}

	// return an empty list if nothing is found
	searchFlavorList, err := controller.FlavorGroupStore.SearchFlavors(fgID)
	if err != nil && strings.Contains(err.Error(), commErr.RowsNotFound) {
		return hvs.FlavorgroupFlavorLinkCollection{FGFLinks: searchResults}, http.StatusOK, nil
	}

	// any other error
	if err != nil {
		defaultLog.WithField("flavorGroup", fgID).WithError(err).Errorf("controllers/flavorgroup_controller:SearchFlavors() %s :  Failed to search linked flavors for FlavorGroup", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search FlavorGroup-Flavor links"}
	}

	// assemble into collection
	for _, lf := range searchFlavorList {
		searchResults = append(searchResults, hvs.FlavorgroupFlavorLink{
			FlavorGroupID: fgID,
			FlavorID:      lf,
		})
	}

	secLog.WithField("flavorGroup", fgID).Infof("%s: Search Flavor-FlavorGroup links filtered by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return hvs.FlavorgroupFlavorLinkCollection{FGFLinks: searchResults}, http.StatusOK, nil
}

// RetrieveFlavor retrieves the FlavorGroupFlavor link in the FlavorGroupStore
func (controller FlavorgroupController) RetrieveFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:RetrieveFlavor() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:RetrieveFlavor() Leaving")

	// Get the FlavorGroup, Flavor ID from the URL
	fgID := uuid.MustParse(mux.Vars(r)["fgID"])
	fID := uuid.MustParse(mux.Vars(r)["fID"])

	// Retrieve flavor links
	fgl, err := controller.FlavorGroupStore.RetrieveFlavor(fgID, fID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithField("flavorGroup", fID).WithField("flavor", fID).WithError(err).Errorf("controllers/flavorgroup_controller:RetrieveFlavor() %s :  Linked Flavors not found ", commLogMsg.AppRuntimeErr)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup-Flavor link does not exist"}
		} else {
			defaultLog.WithField("flavorGroup", fID).WithField("flavor", fID).WithError(err).Errorf("controllers/flavorgroup_controller:RetrieveFlavor() %s :  Error retrieving linked flavor", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to retrieve FlavorGroup-Flavor links"}
		}
	}

	secLog.WithField("flavorGroup", fID).WithField("flavor", fID).Infof("%s: Flavor-FlavorGroup link retrieved by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return fgl, http.StatusOK, nil
}

func (controller FlavorgroupController) getAssociatedFlavorTemplates(flavorGroupID uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:getAssociatedFlavorTemplates() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:getAssociatedFlavorTemplates() Leaving")

	templates, err := controller.FlavorGroupStore.SearchFlavorTemplatesByFlavorGroup(flavorGroupID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to search flavor templates associated with default flavorgroup")
	}
	var templateIds []uuid.UUID
	for _, templateId := range templates {
		templateIds = append(templateIds, templateId)
	}
	return templateIds, nil
}

func (controller FlavorgroupController) getAssociatedFlavorAndTemplates(flavorgroupList []hvs.FlavorGroup, includeFlavorContent bool, filter models.FlavorGroupFilterCriteria) (*hvs.
	FlavorgroupCollection, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:getAssociatedFlavorAndTemplates() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:getAssociatedFlavorAndTemplates() Leaving")

	for index, flavorGroup := range flavorgroupList {
		flavorIds, err := controller.FlavorGroupStore.SearchFlavors(flavorGroup.ID)
		if err != nil {
			return nil, errors.Errorf("Error getting flavor IDs " +
				"linked to flavor group")
		}
		flavorgroupList[index].FlavorIds = flavorIds
		if includeFlavorContent {
			signedFlavorList, err := controller.FlavorStore.Search(&models.FlavorVerificationFC{FlavorFC: models.FlavorFilterCriteria{Ids: flavorIds}})
			if err != nil {
				return nil, errors.Wrap(err, "Error retrieving flavors "+
					"linked to flavor group")
			}
			for _, signedFlavor := range signedFlavorList {
				flavorgroupList[index].Flavors = append(flavorgroupList[index].Flavors, signedFlavor.Flavor)
			}
		}
		flavorgroupList[index].FlavorTemplateIds, err = controller.getAssociatedFlavorTemplates(flavorGroup.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Error retrieving flavor templates linked to flavor group")
		}
	}

	var next, prev string
	if len(flavorgroupList) > 0 {
		lastRowId := flavorgroupList[len(flavorgroupList)-1].RowId
		next, prev = GetNextAndPrevValues(filter.Limit, filter.AfterId, lastRowId, len(flavorgroupList))
	}

	flavorgroupCollection := &hvs.FlavorgroupCollection{
		Flavorgroups: flavorgroupList, Next: next, Previous: prev}
	return flavorgroupCollection, nil
}
