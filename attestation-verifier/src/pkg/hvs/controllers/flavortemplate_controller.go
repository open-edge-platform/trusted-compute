/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/antchfx/jsonquery"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/xeipuuv/gojsonschema"
)

type FlavorTemplateController struct {
	FTStore                 domain.FlavorTemplateStore
	FGStore                 domain.FlavorGroupStore
	CommonDefinitionsSchema string
	FlavorTemplateSchema    string
	DefinitionsSchemaJSON   string
	TemplateSchemaJSON      string
}
type ErrorMessage struct {
	Message string
}

// NewFlavorTemplateController This method is used to initialize the flavorTemplateController
func NewFlavorTemplateController(flavorTemplateStore domain.FlavorTemplateStore, flavorGroupStore domain.FlavorGroupStore,
	commonDefinitionsSchema, flavorTemplateSchema string) *FlavorTemplateController {
	return &FlavorTemplateController{
		FTStore:                 flavorTemplateStore,
		FGStore:                 flavorGroupStore,
		CommonDefinitionsSchema: commonDefinitionsSchema,
		FlavorTemplateSchema:    flavorTemplateSchema,
	}
}

var flavorTemplateSearchParams = map[string]bool{"id": true, "label": true, "conditionContains": true, "flavorPartContains": true, "includeDeleted": true}

// Create This method is used to create the flavor template and store it in the database
func (ftc *FlavorTemplateController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Create() Leaving")

	flavorTemplateReq, err := ftc.getFlavorTemplateCreateReq(r)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Failed to complete create flavor template")
		switch errorType := err.(type) {
		case *commErr.UnsupportedMediaError:
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: errorType.Message}
		case *commErr.BadRequestError:
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: errorType.Message}
		default:
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
		}
	}

	//FTStore this template into database.
	flavorTemplate, err := ftc.FTStore.Create(&flavorTemplateReq.FlavorTemplate)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Failed to create flavor template")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create flavor template"}
	}

	var fgNames []string
	if len(flavorTemplateReq.FlavorgroupNames) != 0 {
		fgNames = flavorTemplateReq.FlavorgroupNames
	} else {
		defaultLog.Debug("Flavorgroup names not present in request, associating with default ones")
		fgNames = append(fgNames, models.FlavorGroupsAutomatic.String())
	}
	flavorGroups, err := GetFlavorGroups(ftc.FGStore, fgNames, nil)
	if err != nil {
		defaultLog.Error("controllers/flavor_controller: createFlavors() Host FlavorGroup not found " + err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}
	defaultLog.Debugf("Associating Flavor-Template %s with flavorgroups %+q", flavorTemplate.ID, fgNames)
	if len(fgNames) > 0 {
		if err := ftc.linkFlavorgroupsToFlavorTemplate(flavorTemplate.ID, flavorGroups); err != nil {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Flavor-Template FlavorGroup association failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Flavor-Template with flavorgroups"}
		}
	}

	return flavorTemplate, http.StatusCreated, nil
}

func (ftc *FlavorTemplateController) linkFlavorgroupsToFlavorTemplate(templateId uuid.UUID, flavorgroups []hvs.FlavorGroup) error {
	defaultLog.Trace("controllers/flavortemplate_controller:linkFlavorgroupsToFlavorTemplate() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:linkFlavorgroupsToFlavorTemplate() Leaving")

	flavorgroupIds := []uuid.UUID{}
	for _, flavorgroup := range flavorgroups {
		linkExists, err := ftc.flavorGroupFlavorTemplateLinkExists(templateId, flavorgroup.ID)
		if err != nil {
			return errors.Wrap(err, "Could not check flavortemplate-flavorgroup link existence")
		}
		if !linkExists {
			flavorgroupIds = append(flavorgroupIds, flavorgroup.ID)
		}
	}

	defaultLog.Debugf("Linking flavortemplate %v with flavorgroups %+q", templateId, flavorgroupIds)
	if len(flavorgroupIds) > 0 {
		if err := ftc.FTStore.AddFlavorgroups(templateId, flavorgroupIds); err != nil {
			return errors.Wrap(err, "Could not create flavortemplate-flavorgroup links")
		}
	}

	return nil
}

// Retrieve This method is used to retrieve a flavor template
func (ftc *FlavorTemplateController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["ftId"])

	flavorTemplate, err := ftc.FTStore.Retrieve(templateID, false)
	if err != nil {
		switch err.(type) {
		case *commErr.StatusNotFoundError:
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() Flavor template with given ID does not exist or has been deleted")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		default:
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() Failed to retrieve FlavorTemplate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorTemplate with the given ID"}
		}
	}
	return flavorTemplate, http.StatusOK, nil
}

// isIncludeDeleted This method is used to return boolean value of query parameter
func isIncludeDeleted(paramIncludeDelete string) (bool, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:isIncludeDeleted() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:isIncludeDeleted() Leaving")

	if paramIncludeDelete != "" {
		switch paramIncludeDelete {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, errors.New("controllers/flavortemplate_controller:isIncludeDeleted() Invalid query parameter given")
		}
	}
	return false, nil
}

// Search This method is used to retrieve all the flavor templates
func (ftc *FlavorTemplateController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Search() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), flavorTemplateSearchParams); err != nil {
		secLog.Errorf("controllers/flavortemplate_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	criteria, err := populateFlavorTemplateFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:Search() %s Invalid filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria"}
	}

	//call store function to retrieve all available templates from DB.
	flavorTemplates, err := ftc.FTStore.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error retrieving all flavor templates")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error retrieving all flavor templates"}
	}

	return flavorTemplates, http.StatusOK, nil
}

// Delete This method is used to delete a flavor template
func (ftc *FlavorTemplateController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Delete() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["ftId"])

	//call store function to delete template from DB.
	if err := ftc.FTStore.Delete(templateID); err != nil {
		switch err.(type) {
		case *commErr.StatusNotFoundError:
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Flavor template with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		default:
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Failed to delete flavor template with given ID")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete flavor template with given ID"}
		}
	}

	return nil, http.StatusNoContent, nil
}

// getFlavorTemplateCreateReq This method is used to get the body content of Flavor Template Create Request
func (ftc *FlavorTemplateController) getFlavorTemplateCreateReq(r *http.Request) (hvs.FlavorTemplateReq, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Leaving")

	var createFlavorTemplateReq hvs.FlavorTemplateReq
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		defaultLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid Content-Type")
		return createFlavorTemplateReq, &commErr.UnsupportedMediaError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		defaultLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() The request body is not provided")
		return createFlavorTemplateReq, &commErr.BadRequestError{Message: "The request body is not provided"}
	}

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&createFlavorTemplateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to decode request body")
		return createFlavorTemplateReq, &commErr.BadRequestError{Message: "Unable to decode request body"}
	}

	if createFlavorTemplateReq.FlavorTemplate.ID != uuid.Nil {
		template, err := ftc.FTStore.Retrieve(createFlavorTemplateReq.FlavorTemplate.ID, true)
		if err != nil {
			switch err.(type) {
			case *commErr.StatusNotFoundError:
				break
			default:
				defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Failed to retrieve flavor template")
				return hvs.FlavorTemplateReq{}, errors.New("Failed to validate flavor template ID")
			}
		}
		if template != nil {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to create flavor template, template with given template ID already exists or has been deleted")
			return hvs.FlavorTemplateReq{}, &commErr.BadRequestError{Message: "FlavorTemplate with given template ID already exists or has been deleted"}
		}
	}

	flavorTemplateBytes, err := json.Marshal(createFlavorTemplateReq.FlavorTemplate)
	if err != nil {
		secLog.WithError(err).Info(
			"controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Failed to marshal FlavorTemplate")
		return hvs.FlavorTemplateReq{}, errors.New("Failed to marshal FlavorTemplate")
	}

	defaultLog.Debug("Validating create flavor request")
	errMsg, err := ftc.ValidateFlavorTemplateCreateRequest(createFlavorTemplateReq.FlavorTemplate, string(flavorTemplateBytes))
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to create flavor template, validation failed")
		return createFlavorTemplateReq, &commErr.BadRequestError{Message: errMsg}
	}

	if len(createFlavorTemplateReq.FlavorTemplate.Condition) == 0 {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to create flavor template, empty condition field provided")
		return hvs.FlavorTemplateReq{}, &commErr.BadRequestError{Message: "Unable to create flavor template, empty condition field provided"}
	}

	return createFlavorTemplateReq, nil
}

func (ftc *FlavorTemplateController) AddFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:AddFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:AddFlavorgroup() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavortemplate_controller:AddFlavorgroup() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqFlavorTemplateFlavorgroup hvs.FlavorTemplateFlavorgroupCreateRequest
	err := dec.Decode(&reqFlavorTemplateFlavorgroup)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:AddFlavorgroup() %s :  Failed to decode request body as FlavorTemplateFlavorgroupCreateRequest", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqFlavorTemplateFlavorgroup.FlavorgroupId == uuid.Nil {
		secLog.Errorf("controllers/flavortemplate_controller:AddFlavorgroup() %s : Invalid Flavorgroup Id specified in request", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Flavorgroup Id specified in request"}
	}

	ftId := uuid.MustParse(mux.Vars(r)["ftId"])
	_, err = ftc.FTStore.Retrieve(ftId, false)
	if err != nil {
		switch err.(type) {
		case *commErr.StatusNotFoundError:
			secLog.WithError(err).WithField("id", ftId).Info(
				"controllers/flavortemplate_controller:AddFlavorgroup() Flavor template with given ID does not exist or has been deleted")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		default:
			secLog.WithError(err).WithField("id", ftId).Info(
				"controllers/flavortemplate_controller:AddFlavorgroup() Failed to retrieve FlavorTemplate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorTemplate with the given ID"}
		}
	}

	_, err = ftc.FGStore.Retrieve(reqFlavorTemplateFlavorgroup.FlavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", reqFlavorTemplateFlavorgroup.FlavorgroupId).Error("controllers/flavortemplate_controller:AddFlavorgroup() Flavorgroup with specified id could not be located")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavorgroup with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", reqFlavorTemplateFlavorgroup.FlavorgroupId).Error("controllers/flavortemplate_controller:AddFlavorgroup() Flavorgroup retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavorgroup from database"}
		}
	}

	linkExists, err := ftc.flavorGroupFlavorTemplateLinkExists(ftId, reqFlavorTemplateFlavorgroup.FlavorgroupId)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:AddFlavorgroup() Flavor Template Flavorgroup link retrieve failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Flavor Template Flavorgroup link"}
	}
	if linkExists {
		secLog.WithError(err).Warningf("%s: Trying to create duplicate Flavor Template Flavorgroup link", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor Template Flavorgroup link with specified ids already exist"}
	}

	defaultLog.Debugf("Linking flavor template %v with flavorgroup %v", ftId, reqFlavorTemplateFlavorgroup.FlavorgroupId)
	err = ftc.FTStore.AddFlavorgroups(ftId, []uuid.UUID{reqFlavorTemplateFlavorgroup.FlavorgroupId})
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:AddFlavorgroup() Flavor Template Flavorgroup association failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate flavor template with Flavorgroup"}
	}

	createdFlavorTemplateFlavorgroup := hvs.FlavorTemplateFlavorgroup{
		FlavortemplateId: ftId,
		FlavorgroupId:    reqFlavorTemplateFlavorgroup.FlavorgroupId,
	}

	secLog.WithField("flavortemplate-flavorgroup-link", createdFlavorTemplateFlavorgroup).Infof("%s: Flavor Template Flavorgroup link created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdFlavorTemplateFlavorgroup, http.StatusCreated, nil
}

func (ftc *FlavorTemplateController) flavorGroupFlavorTemplateLinkExists(ftId, flavorgroupId uuid.UUID) (bool, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:flavorGroupFlavorTemplateLinkExists() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:flavorGroupFlavorTemplateLinkExists() Leaving")

	// retrieve the flavortemplate-flavorgroup link using flavortemplate id and flavorgroup id
	_, err := ftc.FTStore.RetrieveFlavorgroup(ftId, flavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

func (ftc *FlavorTemplateController) RetrieveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:RetrieveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:RetrieveFlavorgroup() Leaving")

	ftId := uuid.MustParse(mux.Vars(r)["ftId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	flavorTemplateFlavorgroup, err := ftc.FTStore.RetrieveFlavorgroup(ftId, fgId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:RetrieveFlavorgroup() Flavor Template Flavorgroup link with specified ids could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor Template Flavorgroup link with specified ids does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:RetrieveFlavorgroup() Flavor Template Foavorgroup link retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor Template Flavorgroup link from database"}
		}
	}

	secLog.WithField("flavortemplate-flavorgroup-link", flavorTemplateFlavorgroup).Infof("%s: Flavor Template Flavorgroup link retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorTemplateFlavorgroup, http.StatusOK, nil
}

func (ftc *FlavorTemplateController) RemoveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:RemoveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:RemoveFlavorgroup() Leaving")

	ftId := uuid.MustParse(mux.Vars(r)["ftId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	flavorTemplateFlavorgroup, err := ftc.FTStore.RetrieveFlavorgroup(ftId, fgId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:RetrieveFlavorgroup() Flavor Template Flavorgroup link with specified ids could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor Template Flavorgroup link with specified ids does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:RetrieveFlavorgroup() Flavor Template Foavorgroup link retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor Template Flavorgroup link from database"}
		}
	}

	if err := ftc.FTStore.RemoveFlavorgroups(ftId, []uuid.UUID{fgId}); err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:RemoveFlavorgroup() Flavor Template Flavorgroup link delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor Template Flavorgroup link"}
	}

	secLog.WithField("flavortemplate-flavorgroup-link", flavorTemplateFlavorgroup).Infof("Flavor Template Flavorgroup link deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (ftc *FlavorTemplateController) SearchFlavorgroups(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:SearchFlavorgroups() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:SearchFlavorgroups() Leaving")

	ftId := uuid.MustParse(mux.Vars(r)["ftId"])
	fgIds, err := ftc.FTStore.SearchFlavorgroups(ftId)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:SearchFlavorgroups() Flavor Template Flavorgroup links search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Flavor Template Flavorgroup links")
	}

	flavorTemplateFlavorgroups := []hvs.FlavorTemplateFlavorgroup{}
	for _, fgId := range fgIds {
		flavorTemplateFlavorgroups = append(flavorTemplateFlavorgroups, hvs.FlavorTemplateFlavorgroup{
			FlavortemplateId: ftId,
			FlavorgroupId:    fgId,
		})
	}
	flavorTemplateFlavorgroupCollection := hvs.FlavorTemplateFlavorgroupCollection{FlavorTemplateFlavorgroups: flavorTemplateFlavorgroups}

	secLog.Infof("%s: Flavor Template Flavorgroup links searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorTemplateFlavorgroupCollection, http.StatusOK, nil
}

// validateFlavorTemplateCreateRequest This method is used to validate the flavor template
func (ftc *FlavorTemplateController) ValidateFlavorTemplateCreateRequest(FlvrTemp hvs.FlavorTemplate, template string) (string, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Leaving")
	// Check whether the template is adhering to the schema
	schemaLoader := gojsonschema.NewSchemaLoader()

	var err error
	if ftc.DefinitionsSchemaJSON == "" {
		ftc.DefinitionsSchemaJSON, err = readJSON(ftc.CommonDefinitionsSchema)
		if err != nil {
			return "Unable to read the common definitions schema", errors.Wrap(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Unable to read the file"+consts.CommonDefinitionsSchema)
		}
	}

	if validationErr := validation.ValidateStrings([]string{FlvrTemp.Label}); validationErr != nil {
		return "Flavor template label is not in valid format", errors.Wrap(validationErr, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Flavor template label is not in valid format")
	}

	definitionsSchema := gojsonschema.NewStringLoader(ftc.DefinitionsSchemaJSON)

	if ftc.TemplateSchemaJSON == "" {
		ftc.TemplateSchemaJSON, err = readJSON(ftc.FlavorTemplateSchema)
		if err != nil {
			return "Unable to read the template schema", errors.Wrap(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Unable to read the file"+consts.FlavorTemplateSchema)
		}
	}

	flvrTemplateSchema := gojsonschema.NewStringLoader(ftc.TemplateSchemaJSON)
	schemaLoader.AddSchemas(definitionsSchema)

	schema, err := schemaLoader.Compile(flvrTemplateSchema)
	if err != nil {
		return "Unable to compile the template", errors.Wrap(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Unable to compile the schemas")
	}

	documentLoader := gojsonschema.NewStringLoader(template)

	result, err := schema.Validate(documentLoader)
	if err != nil {
		return "Unable to validate the template", errors.Wrap(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Unable to validate the template")
	}

	var errorMsg string
	if !result.Valid() {
		for _, desc := range result.Errors() {
			errorMsg = errorMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errorMsg, errors.New("controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() The provided template is not valid" + errorMsg)
	}

	defaultLog.Infof("controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() The provided template with template ID %s is valid", FlvrTemp.ID)

	//Validation the syntax of the conditions
	tempDoc, err := jsonquery.Parse(strings.NewReader("{}"))
	if err != nil {
		return "", errors.Wrap(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Unable to parse json query")
	}

	for _, condition := range FlvrTemp.Condition {
		// Validate and sanitize the condition before using it
		if err := validation.ValidateFlavorTemplateConditionQuery(condition); err != nil {
			return "Invalid syntax in condition statement", errors.Wrapf(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Invalid syntax in condition : %s", condition)
		}

		_, err := jsonquery.Query(tempDoc, condition)
		if err != nil {
			return "Unable to retrieve query condition statement", errors.Wrapf(err, "controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Invalid syntax in condition : %s", condition)
		}
	}

	//Check whether each pcr index is associated with not more than one bank.
	pcrMap := make(map[*hvs.FlavorPart][]hvs.PCR)
	flavorParts := []*hvs.FlavorPart{FlvrTemp.FlavorParts.Platform, FlvrTemp.FlavorParts.OS, FlvrTemp.FlavorParts.HostUnique}
	for _, flavorPart := range flavorParts {
		if flavorPart != nil {
			if _, ok := pcrMap[flavorPart]; !ok {
				var pcrs []hvs.PCR
				for _, pcrRule := range flavorPart.PcrRules {
					pcrs = append(pcrs, pcrRule.Pcr)
				}
				pcrMap[flavorPart] = pcrs
			}
		}
	}

	for _, pcrList := range pcrMap {
		temp := make(map[int]bool)
		for _, pcr := range pcrList {
			if _, ok := temp[pcr.Index]; !ok {
				temp[pcr.Index] = true
			} else {
				return "Template has duplicate banks for same PCR index", errors.New("controllers/flavortemplate_controller:ValidateFlavorTemplateCreateRequest() Template has duplicate banks for same PCR index")
			}
		}
	}

	return "", nil
}

// readJSON This method is used to read the json file
func readJSON(jsonFilePath string) (string, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:readJSON() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:readJSON() Leaving")
	byteValue, err := ioutil.ReadFile(jsonFilePath)
	if err != nil {
		return "", errors.Wrap(err, "controllers/flavortemplate_controller:readJSON() unable to read file"+jsonFilePath)
	}
	return string(byteValue), nil
}

// populateFlavorTemplateFilterCriteria This method is used to populate the flavor template filter criteria
func populateFlavorTemplateFilterCriteria(params url.Values) (*models.FlavorTemplateFilterCriteria, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:populateFlavorTemplateFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:populateFlavorTemplateFilterCriteria() Leaving")

	var criteria models.FlavorTemplateFilterCriteria

	if params.Get("includeDeleted") != "" {
		includeDeleted, err := isIncludeDeleted(params.Get("includeDeleted"))
		if err != nil {
			return nil, errors.Wrap(err, "Invalid query parameter given")
		}
		criteria.IncludeDeleted = includeDeleted
	}

	if params.Get("id") != "" {
		id, err := uuid.Parse(params.Get("id"))
		if err != nil {
			return nil, errors.Wrap(err, "Invalid id query param value, must be UUID")
		}
		criteria.Ids = []uuid.UUID{id}
	}
	if params.Get("label") != "" {
		label := params.Get("label")
		if err := validation.ValidateTextString(label); err != nil {
			return nil, errors.Wrap(err, "Valid contents for label must be specified")
		}
		criteria.Label = label
	}
	if params.Get("conditionContains") != "" {
		condition := params.Get("conditionContains")
		if err := validation.ValidateTextString(condition); err != nil {
			return nil, errors.Wrap(err, "Valid contents for condition must be specified")
		}
		criteria.ConditionContains = condition

	}
	if params.Get("flavorPartContains") != "" {
		flavorPart := params.Get("flavorPartContains")
		if err := validation.ValidateTextString(flavorPart); err != nil {
			return nil, errors.Wrap(err, "Valid contents for flavor part must be specified")
		}
		criteria.FlavorPartContains = strings.ToUpper(flavorPart)
	}

	return &criteria, nil
}
