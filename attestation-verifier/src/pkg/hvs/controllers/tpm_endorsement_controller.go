/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type TpmEndorsementController struct {
	Store domain.TpmEndorsementStore
}

var tpmEndorsementSearchParams = map[string]bool{"id": true, "hardwareUuidEqualTo": true, "issuerEqualTo": true, "revokedEqualTo": true,
	"issuerContains": true, "commentEqualTo": true, "commentContains": true, "certificateDigestEqualTo": true, "afterId": true, "limit": true}

func (controller TpmEndorsementController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Create() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/tpm_endorsement_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqTpmEndorsement hvs.TpmEndorsement
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Create() %s :  Failed to decode request body as TpmEndorsement", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqTpmEndorsement.HardwareUUID == uuid.Nil || reqTpmEndorsement.Certificate == "" || reqTpmEndorsement.Issuer == "" {
		defaultLog.Error("controllers/tpm_endorsement_controller:Create()  hardware_uuid, certificate and issuer must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "hardware_uuid, certificate and issuer must be specified"}
	}

	if err := validateTpmEndorsement(reqTpmEndorsement); err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Create() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in request"}
	}

	existingTpmEndorsement, err := controller.Store.Search(&models.TpmEndorsementFilterCriteria{
		HardwareUuidEqualTo: reqTpmEndorsement.HardwareUUID,
	})
	if existingTpmEndorsement != nil && len(existingTpmEndorsement.TpmEndorsement) > 0 {
		secLog.WithField("HardwareUUID", existingTpmEndorsement.TpmEndorsement[0].HardwareUUID).Warningf("%s: Trying to create duplicated TpmEndorsment from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "TpmEndorsement with same hardware_uuid already exist."}
	}

	reqTpmEndorsement.CertificateDigest, err = getCertDigestForCert(reqTpmEndorsement)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/tpm_endorsement_controller:Create() Error while generating certificate digest")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while generating certificate digest"}
	}
	// Persistence
	newTpmEndorsement, err := controller.Store.Create(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Create() TpmEndorsement create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error on inserting TpmEndorsement"}
	}
	secLog.WithField("HardwareUUID", reqTpmEndorsement.HardwareUUID).Infof("%s: TpmEndorsement created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTpmEndorsement, http.StatusCreated, nil
}

func getCertDigestForCert(tpmEndorsement hvs.TpmEndorsement) (string, error) {
	cert, err := base64.StdEncoding.DecodeString(tpmEndorsement.Certificate)
	if err != nil {
		return "", errors.Wrap(err, "controllers/tpm_endorsement_controller:Update() Error while base64 decoding ek certificate")
	}
	certificateDigest, err := crypt.GetCertHashFromPemInHex(cert, crypto.SHA384)
	if err != nil {
		return "", errors.Wrap(err, "controllers/tpm_endorsement_controller:Update() Error while generating digest of ek certificate")
	}
	return certificateDigest, nil
}

func (controller TpmEndorsementController) Update(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Update() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Update() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/tpm_endorsement_controller:Update() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}
	id := uuid.MustParse(mux.Vars(r)["id"])

	var reqTpmEndorsement hvs.TpmEndorsement
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Update() %s :  Failed to decode request body as TpmEndorsement", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateTpmEndorsement(reqTpmEndorsement); err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Update()  %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in request"}
	}

	tpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", reqTpmEndorsement.ID).Error(
				"controllers/tpm_endorsement_controller:Update() TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", reqTpmEndorsement.ID).Error(
				"controllers/tpm_endorsement_controller:Update() attempt to update invalid TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update TpmEndorsement"}
		}
	}

	if reqTpmEndorsement.Issuer != "" {
		tpmEndorsement.Issuer = reqTpmEndorsement.Issuer
	}

	if reqTpmEndorsement.HardwareUUID != uuid.Nil {
		tpmEndorsement.HardwareUUID = reqTpmEndorsement.HardwareUUID
	}

	if reqTpmEndorsement.Certificate != "" {
		tpmEndorsement.Certificate = reqTpmEndorsement.Certificate
		tpmEndorsement.CertificateDigest, err = getCertDigestForCert(reqTpmEndorsement)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/tpm_endorsement_controller:Update() Error while generating certificate digest")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while generating certificate digest"}
		}
	}

	if reqTpmEndorsement.Comment != "" {
		tpmEndorsement.Comment = reqTpmEndorsement.Comment
	}

	if tpmEndorsement.Revoked != reqTpmEndorsement.Revoked {
		tpmEndorsement.Revoked = reqTpmEndorsement.Revoked
	}
	// Persistence
	newTpmEndorsement, err := controller.Store.Update(tpmEndorsement)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Update() TpmEndorsement update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error on Saving TpmEndorsement"}
	}
	secLog.WithField("HardwareUUID", reqTpmEndorsement.HardwareUUID).Infof("%s: TpmEndorsement updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTpmEndorsement, http.StatusOK, nil
}

func (controller TpmEndorsementController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query tpmendorsements")
	if err := utils.ValidateQueryParams(r.URL.Query(), tpmEndorsementSearchParams); err != nil {
		secLog.Errorf("controllers/tpm_endorsement_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	filter, err := getAndValidateFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Search() %s Invalid input provided in filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in filter criteria"}
	}
	tpmEndorsementCollection, err := controller.Store.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Search() TpmEndorsement get all failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search TpmEndorsement"}
	}

	var next, prev string
	if len(tpmEndorsementCollection.TpmEndorsement) > 0 {
		lastRowId := tpmEndorsementCollection.TpmEndorsement[len(tpmEndorsementCollection.TpmEndorsement)-1].RowId
		next, prev = GetNextAndPrevValues(filter.Limit, filter.AfterId, lastRowId, len(tpmEndorsementCollection.TpmEndorsement))
	}

	tpmEndorsementCollection.Next = next
	tpmEndorsementCollection.Previous = prev

	secLog.Infof("%s: Return tpm-endorsement query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tpmEndorsementCollection, http.StatusOK, nil
}

func (controller TpmEndorsementController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delTpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Delete()  TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Delete() attempt to delete invalid TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TpmEndorsement"}
		}
	}

	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/tpm_endorsement_controller:Delete() failed to delete TpmEndorsement")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TpmEndorsement"}
	}
	secLog.WithField("ID", delTpmEndorsement.ID).Infof("TpmEndorsement deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller TpmEndorsementController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	tpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Retrieve() TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Retrieve() failed to retrieve TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve TpmEndorsement"}
		}
	}

	secLog.WithField("ID", tpmEndorsement.ID).Infof("TpmEndorsement retrieved by: %s", r.RemoteAddr)
	return tpmEndorsement, http.StatusOK, nil
}

func (controller TpmEndorsementController) DeleteCollection(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:DeleteCollection() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:DeleteCollection() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query tpmendorsements")

	filter, err := getAndValidateFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:DeleteCollection() %s Invalid input provided in filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in filter criteria"}
	}

	tpmEndorsements, err := controller.Store.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:DeleteCollection() failed to search TpmEndorsements for given criteria")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search TpmEndorsements for given criteria"}
	}

	if len(tpmEndorsements.TpmEndorsement) == 0 {
		return nil, http.StatusNoContent, nil
	}

	for _, te := range tpmEndorsements.TpmEndorsement {
		err := controller.Store.Delete(te.ID)
		if err != nil {
			defaultLog.WithError(err).Errorf("Failed to delete TpmEndorsements for ID %s", te.ID.String())
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TpmEndorsements for given criteria"}
		}
	}
	secLog.Infof("TpmEndorsements deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func getAndValidateFilterCriteria(params url.Values) (*models.TpmEndorsementFilterCriteria, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:getAndValidateFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:getAndValidateFilterCriteria() Leaving")
	var criteria models.TpmEndorsementFilterCriteria
	id := params.Get("id")
	hwId := params.Get("hardwareUuidEqualTo")
	issuerEqualTo := params.Get("issuerEqualTo")
	revokedEqualTo := params.Get("revokedEqualTo")
	issuerContains := params.Get("issuerContains")
	commentEqualTo := params.Get("commentEqualTo")
	commentContains := params.Get("commentContains")
	certificateDigestEqualTo := params.Get("certificateDigestEqualTo")

	if id != "" {
		id, err := uuid.Parse(id)
		if err != nil {
			return nil, errors.New("Invalid id query param value, must be UUID")
		}
		criteria.Id = id
	}
	if hwId != "" {
		hwId, err := uuid.Parse(hwId)
		if err != nil {
			return nil, errors.New("Invalid hardwareUuidEqualTo query param value, must be UUID")
		}
		criteria.HardwareUuidEqualTo = hwId
	}
	if issuerEqualTo != "" {
		if err := validation.ValidateIssuer(issuerEqualTo); err != nil {
			return nil, errors.Wrap(err, "Valid contents for IssuerEqualTo must be specified")
		}
		criteria.IssuerEqualTo = issuerEqualTo
	}

	if issuerContains != "" {
		if err := validation.ValidateIssuer(issuerContains); err != nil {
			return nil, errors.Wrap(err, "Valid contents for IssuerContains must be specified")
		}
		criteria.IssuerContains = issuerContains
	}

	if commentContains != "" {
		if err := validation.ValidateStrings(strings.Split(commentContains, " ")); err != nil {
			return nil, errors.Wrap(err, "Valid contents for CommentContains must be specified")
		}
		criteria.CommentContains = commentContains
	}
	if commentEqualTo != "" {
		if err := validation.ValidateStrings(strings.Split(commentEqualTo, " ")); err != nil {
			return nil, errors.Wrap(err, "Valid contents for CommentEqualTo must be specified")
		}
		criteria.CommentEqualTo = commentEqualTo
	}
	criteria.RevokedEqualTo = false
	if revokedEqualTo != "" {
		if revoked, err := strconv.ParseBool(revokedEqualTo); err != nil {
			return nil, errors.Wrap(err, "Valid contents for RevokedEqualTo must be specified")
		} else {
			criteria.RevokedEqualTo = revoked
		}
	}

	if certificateDigestEqualTo != "" {
		if err := validation.ValidateHexString(certificateDigestEqualTo); err != nil {
			return nil, errors.New("Valid contents for CertificateDigestEqualTo must be specified")
		}
		criteria.CertificateDigestEqualTo = certificateDigestEqualTo
	}

	limit, afterId, err := validation.ValidatePaginationValues(params.Get("limit"), params.Get("afterId"))
	if err != nil {
		return nil, err
	}
	criteria.Limit = limit
	criteria.AfterId = afterId

	return &criteria, nil
}

func validateTpmEndorsement(reqTpmEndorsement hvs.TpmEndorsement) error {
	defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsement() Entering")
	defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsement() Leaving")

	if _, err := base64.StdEncoding.DecodeString(reqTpmEndorsement.Certificate); err != nil {
		return errors.Wrap(err, "Valid contents for Certificate must be specified")
	}

	if err := validation.ValidateIssuer(reqTpmEndorsement.Issuer); err != nil {
		return errors.Wrap(err, "Valid contents for Issuer must be specified")
	}

	if reqTpmEndorsement.Comment != "" {
		if err := validation.ValidateStrings(strings.Split(reqTpmEndorsement.Comment, " ")); err != nil {
			return errors.Wrap(err, "Valid contents for Comment must be specified")
		}
	}

	return nil
}
