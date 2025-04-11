/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	asset_tag "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/asset-tag"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/util"
	hostConnector "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// TagCertificateController contains logic for handling TagCertificate API requests
type TagCertificateController struct {
	// Config contains the required values sourced from the VS configuration
	Config domain.TagCertControllerConfig
	// TagCertStore is required to source the Signing Keys and Certificates
	CertStore crypt.CertificatesStore
	// Store is used to hold a reference to the backend store for the TagCertificates
	Store domain.TagCertificateStore
	// HostStore is used to hold a reference to the backend store for the Host records
	HostStore domain.HostStore
	// FlavorController holds a reference to the FlavorController, needed to create AssetTag Flavor
	// and assign to the appropriate FlavorGroup
	FlavorController FlavorController
	// HostConnectorProvider is required for providing a HostConnector for connecting to the host during the Deploy Tag Certificate workflow
	HostConnectorProvider hostConnector.HostConnectorProvider
}

func NewTagCertificateController(tc domain.TagCertControllerConfig, certStore crypt.CertificatesStore, tcs domain.TagCertificateStore,
	htm domain.HostTrustManager, hs domain.HostStore, fs domain.FlavorStore, fgs domain.FlavorGroupStore, hcp hostConnector.HostConnectorProvider) *TagCertificateController {

	// CertStore should have an entry for Tag CA Cert
	tagKey, tagCerts, err := certStore.GetKeyAndCertificates(models.CaCertTypesTagCa.String())
	if err != nil || tagKey == nil || tagCerts == nil {
		defaultLog.Errorf("Error while retrieving certificate and key for certType %s", models.CaCertTypesTagCa.String())
		return nil
	}

	flvrSigningkey, _, err := certStore.GetKeyAndCertificates(models.CertTypesFlavorSigning.String())
	if err != nil || flvrSigningkey == nil {
		defaultLog.Errorf("Error while retrieving certificate and key for certType %s", models.CertTypesFlavorSigning.String())
		return nil
	}

	fCon := FlavorController{
		FStore:    fs,
		FGStore:   fgs,
		HStore:    hs,
		HTManager: htm,
	}

	return &TagCertificateController{
		Config:                tc,
		CertStore:             certStore,
		Store:                 tcs,
		HostStore:             hs,
		FlavorController:      fCon,
		HostConnectorProvider: hcp,
	}
}

// Create creates a new TagCertificate x509.Certificate entry into the database
// that can be used to provision an AssetTag on a desired host.
func (controller TagCertificateController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Create() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Errorf("controllers/tagcertificate_controller:Create() %s : The request body is not provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqTCCriteria models.TagCertificateCreateCriteria

	// Decode incoming json data
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTCCriteria)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tagcertificate_controller:Create() %s : Failed to decode request body as TagCertificateCreateCriteria", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	// validate Tag Certificate creation params
	if err := validateTagCertCreateCriteria(reqTCCriteria); err != nil {
		secLog.WithError(err).Errorf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error during Tag Certificate creation - " + err.Error()}
	}

	// get the Tag CA Cert from the certstore
	tagCA := controller.CertStore[models.CaCertTypesTagCa.String()]
	var tagCACert = tagCA.Certificates[0]

	// Initialize the TagCertConfig
	newTCConfig := hvs.TagCertConfig{
		SubjectUUID:       reqTCCriteria.HardwareUUID.String(),
		PrivateKey:        tagCA.Key,
		TagCACert:         &tagCACert,
		TagAttributes:     reqTCCriteria.SelectionContent,
		ValidityInSeconds: consts.DefaultTagCertValiditySeconds,
	}

	// build the x509.Certificate
	atCreator := asset_tag.NewAssetTag()
	newAssetTagBytes, err := atCreator.CreateAssetTag(newTCConfig)
	if err != nil {
		defaultLog.Errorf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	newX509TC, err := x509.ParseCertificate(newAssetTagBytes)
	if err != nil {
		defaultLog.Errorf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	// put this in an X509AttributeCert to extract the properties easily
	tempX509AttrCert, err := hvs.NewX509AttributeCertificate(newX509TC)
	if err != nil {
		defaultLog.Errorf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	// convert to a TagCertificate
	newTagCert := hvs.TagCertificate{
		Certificate:  newAssetTagBytes,
		Subject:      tempX509AttrCert.Subject,
		Issuer:       tagCACert.Issuer.String(),
		NotBefore:    newX509TC.NotBefore.UTC(),
		NotAfter:     newX509TC.NotAfter.UTC(),
		HardwareUUID: reqTCCriteria.HardwareUUID,
	}

	// set TagDigest
	newTagCert.SetAssetTagDigest()

	// persist to DB
	newTC, err := controller.Store.Create(&newTagCert)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tagcertificate_controller:Create() %s : TagCertificate Creation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("Error while persisting TagCertificate to DB")
	}
	secLog.WithField("Name", newTC.Subject).Infof("%s: TagCertificate created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTC, http.StatusCreated, nil
}

// Search returns a collection of TagCertificates based on TagCertificateFilterCriteria
func (controller TagCertificateController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Search() Leaving")

	var tagCertSearchParams = map[string]bool{"id": true, "hardwareUuid": true, "subjectContains": true, "subjectEqualTo": true,
		"issuerContains": true, "issuerEqualTo": true, "validOn": true, "validBefore": true, "validAfter": true}

	if err := utils.ValidateQueryParams(r.URL.Query(), tagCertSearchParams); err != nil {
		secLog.Errorf("controllers/tagcertificate_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// get the TagCertificateFilterCriteria
	filter, err := getTCFilterCriteria(r.URL.Query())
	if err != nil {
		defaultLog.Errorf("controllers/tagcertificate_controller:Search() %s : %s", commLogMsg.InvalidInputBadParam, err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria"}
	}

	tagCertResultSet, err := controller.Store.Search(filter)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tagcertificate_controller:Search() %s : TagCertificate search operation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("TagCertificate search operation failed")
	}

	// add the asset tag digest to all the results
	for _, tc := range tagCertResultSet {
		tc.SetAssetTagDigest()
	}

	tagCertCollection := hvs.TagCertificateCollection{TagCertificates: tagCertResultSet}

	secLog.Infof("%s: Return TagCertificate Search query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tagCertCollection, http.StatusOK, nil
}

// Delete deletes an existing TagCertificate from the backend by its unique ID
func (controller TagCertificateController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Delete() Leaving")

	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).WithField("id", id).Info(
			"controllers/tagcertificate_controller:Delete() Could not parse given ID")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Could not parse given ID"}
	}
	delTagCert, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/tagcertificate_controller:Delete() TagCertificate with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TagCertificate with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/tagcertificate_controller:Delete() attempt to delete invalid TagCertificate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TagCertificate"}
		}
	}

	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/tagcertificate_controller:Delete() failed to delete TagCertificate")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TagCertificate"}
	}
	secLog.WithField("subject", delTagCert.Subject).Infof("TagCertificate deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

// validateTagCertCreateCriteria validates the data from the Create TagCertificate request
func validateTagCertCreateCriteria(tcCreateCriteria models.TagCertificateCreateCriteria) error {
	defaultLog.Trace("controllers/tagcertificate_controller:validateTagCertCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:validateTagCertCreateCriteria() Leaving")

	// validate hardware UUID
	if tcCreateCriteria.HardwareUUID == uuid.Nil {
		return errors.New("Hardware UUID must be specified")
	}

	// if Selection content is empty
	if tcCreateCriteria.SelectionContent == nil {
		return errors.New("Tag Selection Content must be specified")
	}

	for _, tagAttribute := range tcCreateCriteria.SelectionContent {
		if err := validation.ValidateTextString(tagAttribute.Key); err != nil {
			return errors.New("Valid contents for Key must be specified")
		}
		if err := validation.ValidateTextString(tagAttribute.Value); err != nil {
			return errors.New("Valid contents for Value must be specified")
		}
	}

	return nil
}

//  getTCFilterCriteria checks for set filter params in the Search request and returns a valid TagCertificateFilterCriteria
func getTCFilterCriteria(params url.Values) (*models.TagCertificateFilterCriteria, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:getTCFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:getTCFilterCriteria() Leaving")

	tagCertFc := models.TagCertificateFilterCriteria{}

	// TagCertificate ID
	if param := strings.TrimSpace(params.Get("id")); param != "" {
		id, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.New("Invalid UUID format of the TagCertificate Identifier specified")
		}
		tagCertFc.ID = id
	}

	// subjectEqualTo
	if param := strings.TrimSpace(params.Get("subjectEqualTo")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectEqualTo must be specified")
		}
		tagCertFc.SubjectEqualTo = param
	}

	// subjectContains
	if param := strings.TrimSpace(params.Get("subjectContains")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectContains must be specified")
		}
		tagCertFc.SubjectContains = param
	}

	// issuerEqualTo
	if param := strings.TrimSpace(params.Get("issuerEqualTo")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			tagCertFc.IssuerEqualTo = param
		} else {
			return nil, errors.New("Valid contents for issuerEqualTo must be specified")
		}
	}

	// issuerContains
	if param := strings.TrimSpace(params.Get("issuerContains")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			tagCertFc.IssuerContains = param
		} else {
			return nil, errors.New("Valid contents for issuerContains must be specified")
		}
	}

	// validOn
	if param := strings.TrimSpace(params.Get("validOn")); param != "" {
		pTime, err := utils.ParseDateQueryParam(param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for validOn must be specified")
		}
		tagCertFc.ValidOn = pTime
	}

	// validBefore
	if param := strings.TrimSpace(params.Get("validBefore")); param != "" {
		pTime, err := utils.ParseDateQueryParam(param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for validBefore must be specified")
		}
		tagCertFc.ValidBefore = pTime
	}

	// validAfter
	if param := strings.TrimSpace(params.Get("validAfter")); param != "" {
		pTime, err := utils.ParseDateQueryParam(param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for validAfter must be specified")
		}
		tagCertFc.ValidAfter = pTime
	}

	// hardwareUuid
	if param := strings.TrimSpace(params.Get("hardwareUuid")); param != "" {
		hwUUID, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host HardwareUUID specified")
		}
		tagCertFc.HardwareUUID = hwUUID
	}

	return &tagCertFc, nil
}

// Deploy retrieves the specified asset tag certificate, verifies it, and
// deploys it to the host specified in the asset tag certificate subject.
// If the asset tag certificate is successfully deployed to the host, an
// ASSET_TAG flavor is created for the host and the host is queued for flavor
// verification.The TagCertificates REST API is used to manage the certificates
// that are deployed on the host.
func (controller TagCertificateController) Deploy(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Deploy() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Deploy() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	// body should be populated
	if r.ContentLength == 0 {
		secLog.Error("controllers/tagcertificate_controller:Deploy() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	// Decode incoming json data
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var dtcReq models.TagCertificateDeployCriteria

	err := dec.Decode(&dtcReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tagcertificate_controller:Deploy() %s : Failed to decode request body as TagCertificate", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	// check if certificateID is populated
	if dtcReq.CertID == uuid.Nil {
		secLog.WithError(err).WithField("id", dtcReq.CertID).Errorf(
			"controllers/tagcertificate_controller:Deploy() %s : Invalid UUID format of the identifier provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid UUID format of the Tag Certificate identifier provided"}
	}

	defaultLog.Debug("RPC: DeployTagCertificate - Got request to deploy certificate with ID {}", dtcReq.CertID)

	tc, err := controller.Store.Retrieve(dtcReq.CertID)
	if err != nil {
		secLog.WithError(err).WithField("id", dtcReq.CertID).Errorf(
			"controllers/tagcertificate_controller:Deploy() %s : Error retrieving TagCertificate", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Tag Certificate does not exist"}
	}
	tc.SetAssetTagDigest()

	// Ascertain Validity of Tag Certificate
	log.Debug("controllers/tagcertificate_controller:Deploy() Got tagCertificate with ID {}. Checking validity.", dtcReq.CertID)
	// verify certificate validity
	today := time.Now()
	defaultLog.Debug("controllers/tagcertificate_controller:Deploy() Tag Cert not before: {}", tc.NotBefore)
	defaultLog.Debug("controllers/tagcertificate_controller:Deploy() Tag Cert not after: {}", tc.NotAfter)
	defaultLog.Debug("controllers/tagcertificate_controller:Deploy() Time now: {}", today)
	if today.Before(tc.NotBefore) {
		secLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Certificate with Subject %s is not yet valid", commLogMsg.InvalidInputBadParam, tc.Subject)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}
	if today.After(tc.NotAfter) {
		secLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Certificate with Subject %s has expired", commLogMsg.InvalidInputBadParam, tc.Subject)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// lookup Host by Host HardwareUUID
	defaultLog.WithField("HardwareUUID", tc.HardwareUUID).Debug("controllers/tagcertificate_controller:Deploy() Looking up Host")
	hosts, err := controller.HostStore.Search(&models.HostFilterCriteria{
		HostHardwareId: tc.HardwareUUID}, nil)

	// handle zero records returned
	if len(hosts) == 0 || err != nil {
		defaultLog.WithError(err).WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() The Host lookup with specified hardware UUID %s failed", tc.HardwareUUID)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Tag Certificate Deploy failure: Target Host lookup failed"}
	}

	// Unwrap the first Host record from the collection
	targetHost := hosts[0]
	defaultLog.WithField("HardwareUUID", targetHost.HardwareUuid).Debugf("controllers/tagcertificate_controller:Deploy() Found Host with ID %s", targetHost.Id)

	// populate service credentials for AAS
	hostConnStr := fmt.Sprintf("%s;u=%s;p=%s", targetHost.ConnectionString, controller.Config.ServiceUsername, controller.Config.ServicePassword)

	// initialize HostConnector and test connectivity
	hc, err := controller.HostConnectorProvider.NewHostConnector(hostConnStr)
	if err != nil {
		defaultLog.WithError(err).WithField("Certid", dtcReq.CertID).Error("controllers/tagcertificate_controller:Deploy() Failed "+
			"to initialize HostConnector for host with hardware UUID %s", tc.HardwareUUID.String())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure: Target Host connection failed"}
	}

	// DeployAssetTag
	err = asset_tag.NewAssetTag().DeployAssetTag(hc, tc.TagCertDigest, targetHost.HardwareUuid.String())
	if err != nil {
		defaultLog.WithError(err).WithField("Certid", dtcReq.CertID).Error("controllers/tagcertificate_controller:Deploy() Failed "+
			"to deploy Asset Tag on Host %s", targetHost.HardwareUuid)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// get Host Manifest
	hmanifest, err := hc.GetHostManifest(nil)
	if err != nil {
		defaultLog.WithField("id", dtcReq.CertID).Error("controllers/tagcertificate_controller:Deploy() Failed "+
			"to get the HostManifest from Host %s", targetHost.HardwareUuid.String())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	newX509TC, err := x509.ParseCertificate(tc.Certificate)
	if err != nil {
		defaultLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Failed to parse x509.Certificate from TagCert %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// Create AssetTag Flavor for the Host
	fProvider, err := flavor.NewPlatformFlavorProvider(&hmanifest, newX509TC, nil)
	if err != nil {
		defaultLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Failed to initialize FlavorProvider %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// get the asset tag flavor
	assetTagFlavor, err := fProvider.GetPlatformFlavor()
	if err != nil {
		defaultLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Failed to generate AssetTag Flavor %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// get the Flavor Signing Key from the certstore
	var flavorSignKey = controller.CertStore[models.CertTypesFlavorSigning.String()].Key

	// get the signed flavor
	unsignedFlavors, err := (*assetTagFlavor).GetFlavorPartRaw(hvs.FlavorPartAssetTag)
	if err != nil {
		defaultLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Error while getting unsigned Flavor %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	sf, err := util.PlatformFlavorUtil{}.GetSignedFlavor(&unsignedFlavors[0], flavorSignKey.(*rsa.PrivateKey))
	if err != nil {
		defaultLog.WithField("Certid", dtcReq.CertID).Errorf("controllers/tagcertificate_controller:Deploy() %s : Error while getting signed Flavor %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Deploy failure"}
	}

	// Link signed asset tag flavor to the Host Unique FlavorGroup
	var flavorPartMap = make(map[hvs.FlavorPartName][]hvs.SignedFlavor)
	flavorPartMap[hvs.FlavorPartAssetTag] = []hvs.SignedFlavor{*sf}

	linkedSf, err := controller.FlavorController.addFlavorToFlavorgroup(flavorPartMap, nil)
	if err != nil || linkedSf == nil {
		defaultLog.WithError(err).WithField("Certid", dtcReq.CertID).WithField("flavorID", sf.Flavor.Meta.ID).
			Errorf("controllers/tagcertificate_controller:Deploy() %s : Failed to link SignedFlavor to Host "+
				"Unique FlavorGroup", commLogMsg.AppRuntimeErr)
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor with same id/label already exists"}
		}
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error during Tag Certificate Deploy"}
	}

	defaultLog.WithField("Certid", dtcReq.CertID).WithField("flavorID", sf.Flavor.Meta.ID).Debugf("controllers/tagcertificate_controller:Deploy() : Created Asset Tag Deploy Cert")

	secLog.WithField("Certid", dtcReq.CertID).WithField("HardwareUUID", targetHost.HardwareUuid).Infof("%s: TagCertificate deployed by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return sf, http.StatusOK, nil
}
