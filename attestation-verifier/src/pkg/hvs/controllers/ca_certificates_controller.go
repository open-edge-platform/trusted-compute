/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"net/http"
)

type CaCertificatesController struct {
	CertStore *crypt.CertificatesStore
}

var caCertificatesSearchParams = map[string]bool{"domain": true}

// Create stores new CA certificate in the root certificates directory location
func (ca CaCertificatesController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Create() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/ca_certificates_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var caCertificate hvs.CaCertificate
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&caCertificate)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s :  Failed to decode request body as CaCertificates", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	certificate, err := validateCaCertificates(caCertificate)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s : Validation failed for certificate", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	err = ca.CertStore.AddCertificatesToStore(models.GetUniqueCertType(caCertificate.Type), caCertificate.Name, certificate)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s : Failed to store certificate", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to store certificate"}
	}
	secLog.WithField("Name", caCertificate.Name).Infof("%s: CA certificate created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return &caCertificate, http.StatusCreated, nil
}

// Retrieve returns an existing CA certificate from the stored location
func (ca CaCertificatesController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Retrieve() Leaving")

	certType := mux.Vars(r)["certType"]
	certType = models.GetUniqueCertType(certType)
	if !models.IsValidCertType(certType) {
		secLog.Info(
			"controllers/ca_certificates_controller:Retrieve() Invalid Certificate Type provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Certificate Type provided"}
	}

	certificate, err := ReadCertificate(certType, ca.CertStore)
	if err != nil {
		defaultLog.WithError(err).Errorf("Certificates with specified type have not been created/loaded")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Certificates with specified type have not been created/loaded"}
	}
	return certificate, http.StatusOK, nil
}

// Search returns a collection of Ca certificates based on domain
func (ca CaCertificatesController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Search() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Search() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), caCertificatesSearchParams); err != nil {
		secLog.Errorf("controllers/ca_certificates_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	certificates, status, err := ca.searchCertificates(r.URL.Query().Get("domain"))
	if err != nil {
		secLog.WithError(err).Info("controllers/ca_certificates_controller:Search() Error retrieving certificates")
		return nil, status, err
	}
	return certificates, status, nil
}

// SearchPem returns a collection of Ca certificates in Pem format based on domain
func (ca CaCertificatesController) SearchPem(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:SearchPem() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:SearchPem() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), caCertificatesSearchParams); err != nil {
		secLog.Errorf("controllers/ca_certificates_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	certificateCollection, status, err := ca.searchCertificates(r.URL.Query().Get("domain"))
	if err != nil {
		secLog.WithError(err).Info("controllers/ca_certificates_controller:SearchPem() Error retrieving certificates")
		return nil, status, err
	}

	certificates := ""
	for _, caCertificate := range certificateCollection.CaCerts {
		certificateBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCertificate.Certificate,
		}
		certificates = certificates + string(pem.EncodeToMemory(&certificateBlock))
	}
	return certificates, status, nil
}

func (ca CaCertificatesController) searchCertificates(domain string) (*hvs.CaCertificateCollection, int, error) {

	domain = models.GetUniqueCertType(domain)
	if !models.IsValidDomainType(domain) {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid domain/Certificate Type provided"}
	}

	certificates, err := ReadCertificates(domain, ca.CertStore)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Certificates with specified domain have not been created/loaded"}
	}
	return certificates, http.StatusOK, nil
}

// validateCaCertificates checks if input ca certificate is valid
func validateCaCertificates(caCertificate hvs.CaCertificate) (*x509.Certificate, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:validateCaCertificates() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:validateCaCertificates() Leaving")

	if !(models.CaCertTypesRootCa.String() == caCertificate.Type ||
		models.CaCertTypesEndorsementCa.String() == caCertificate.Type ||
		models.CaCertTypesEkCa.String() == caCertificate.Type) {
		return nil, errors.Errorf("Invalid type, only root or endorsement ca certificate can be added")
	}

	certificate, err := x509.ParseCertificate(caCertificate.Certificate)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to decode certificate present in the request body")
	}

	name := caCertificate.Name
	if name == "" {
		return nil, errors.Errorf("Certificate Name must be specified")
	}
	return certificate, nil
}

// Read CaCertificates/certificate from the given certificate path
func ReadCertificates(certType string, certStore *crypt.CertificatesStore) (*hvs.CaCertificateCollection, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificates() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificates() Leaving")

	certsCollection := hvs.CaCertificateCollection{
		CaCerts: []*hvs.CaCertificate{},
	}

	cs := (*certStore)[certType]
	if cs == nil || cs.Certificates == nil || len(cs.Certificates) == 0 {
		return nil, errors.Errorf("%s Certificates have not been loaded", certType)
	}
	for _, cert := range cs.Certificates {
		certificate := hvs.CaCertificate{
			Name:        cert.Subject.CommonName,
			Certificate: cert.Raw,
		}
		certsCollection.CaCerts = append(certsCollection.CaCerts, &certificate)
	}
	return &certsCollection, nil
}

// Read CaCertificate/certificate from the given certificate path
func ReadCertificate(certType string, certStore *crypt.CertificatesStore) (*hvs.CaCertificate, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificate() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificate() Leaving")

	certCollection, err := ReadCertificates(certType, certStore)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/ca_certificates_controller:ReadCertificate() Error while reading "+
			"'%s' certificates"+certType)
	}

	if len(certCollection.CaCerts) > 0 {
		if certType == models.CaCertTypesEndorsementCa.String() {
			cert, err := certStore.RetrieveCertificate(certType, viper.GetString(config.EndorsementCaCommonName))
			if err != nil || cert == nil {
				defaultLog.Errorf("Error while retrieving certificate and key for certType %s", models.CaCertTypesEndorsementCa.String())
				return nil, err
			}
			hvsCert := hvs.CaCertificate{
				Name:        cert.Subject.CommonName,
				Type:        models.CaCertTypesEndorsementCa.String(),
				Certificate: cert.Raw,
			}
			return &hvsCert, nil
		}
		return certCollection.CaCerts[0], nil
	}
	return nil, errors.Wrap(err, "controllers/ca_certificates_controller:ReadCertificate() Certificate not found")
}
