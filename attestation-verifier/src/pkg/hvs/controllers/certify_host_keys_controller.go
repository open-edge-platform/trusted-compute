/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	"github.com/pkg/errors"
	"strings"

	"encoding/json"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"net/http"
)

type CertifyHostKeysController struct {
	CertStore *crypt.CertificatesStore
}

func NewCertifyHostKeysController(certStore *crypt.CertificatesStore) *CertifyHostKeysController {
	// CertStore should have an entry for Privacyca key
	pcaKey, pcaCerts, err := certStore.GetKeyAndCertificates(models.CaCertTypesPrivacyCa.String())
	if err != nil || pcaKey == nil || pcaCerts == nil {
		defaultLog.Errorf("Error while retrieving certificate and key for certType %s", models.CaCertTypesPrivacyCa.String())
		return nil
	}
	return &CertifyHostKeysController{CertStore: certStore}
}

func (certifyHostKeysController *CertifyHostKeysController) CertifySigningKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_keys_controller:CertifySigningKey() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:CertifySigningKey() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	var regKeyInfo model.RegisterKeyInfo
	dec := json.NewDecoder(r.Body)
	defaultLog.Info(dec)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&regKeyInfo); err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_keys_controller:CertifySigningKey() %s Error while decoding request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error while decoding request body"}
	}

	certificate, err, httpStatus := certifyHostKeysController.generateCertificate(consts.HostSigningKeyCertificateCN, regKeyInfo)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:CertifySigningKey() Error while certifying Signing Key")
		return nil, httpStatus, &commErr.ResourceError{Message: "Error while certifying Signing Key"}
	}

	w.WriteHeader(http.StatusCreated)
	signingKeyCert := model.SigningKeyCert{
		SigningKeyCertificate: certificate,
	}
	return signingKeyCert, http.StatusCreated, nil
}

func (certifyHostKeysController *CertifyHostKeysController) CertifyBindingKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_keys_controller:CertifyBindingKey() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:CertifyBindingKey() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	var regKeyInfo model.RegisterKeyInfo
	dec := json.NewDecoder(r.Body)
	defaultLog.Info(dec)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&regKeyInfo); err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_keys_controller:CertifyBindingKey() %s Error while decoding request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error while decoding request body"}
	}

	certificate, err, httpStatus := certifyHostKeysController.generateCertificate(consts.HostBindingKeyCertificateCN, regKeyInfo)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:CertifyBindingKey() Error while certifying Binding Key")
		return nil, httpStatus, &commErr.ResourceError{Message: "Error while certifying Binding Key"}
	}
	bindingKeyCert := model.BindingKeyCert{
		BindingKeyCertificate: certificate,
	}
	return bindingKeyCert, http.StatusCreated, nil
}

func (certifyHostKeysController *CertifyHostKeysController) generateCertificate(commName string, regKeyInfo model.RegisterKeyInfo) ([]byte, error, int) {
	defaultLog.Trace("controllers/certify_host_keys_controller:generateCertificate() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:generateCertificate() Leaving")

	if regKeyInfo.PublicKeyModulus == nil || regKeyInfo.TpmCertifyKey == nil || regKeyInfo.TpmCertifyKeySignature == nil ||
		regKeyInfo.AikDerCertificate == nil || regKeyInfo.NameDigest == nil {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Invalid input specified or input value missing"), http.StatusBadRequest
	}

	//Currently supported only for linux systems
	if strings.ToLower(regKeyInfo.OsType) != "linux" {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Supported only for OS linux"), http.StatusBadRequest
	}

	aikCert, err := x509.ParseCertificate(regKeyInfo.AikDerCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Could not get aik certificate from aik der bytes"), http.StatusBadRequest
	}

	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfo)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Could not certify AIK"), http.StatusInternalServerError
	}

	if !certifyKey20.IsTpmGeneratedKey() {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Not a valid tpm generated key"), http.StatusBadRequest
	}

	// Need to verify if the AIK is signed by the trusted Privacy CA, which would also ensure that the EK is verified.
	if !certifyHostKeysController.isAikCertifiedByPrivacyCA(aikCert) {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Error verifying the AIK signature against the Privacy CA"), http.StatusBadRequest
	}

	rsaPubKey, err := certifyKey20.GetPublicKeyFromModulus()
	if err != nil {
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Error while retrieving public key modulus"), http.StatusBadRequest
	}

	status, err := certifyKey20.IsCertifiedKeySignatureValid(aikCert)
	if err != nil || !status {
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Signature verification failed"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() TpmCertifyKeySignature is validated successfully")

	//In TPM 2.0 need to validate TPM name given to each key
	isKeyValid, err := certifyKey20.ValidatePublicKey()
	if !isKeyValid || err != nil {
		return nil, errors.New("Binding Public Key digest does not match digest in the TCG binding certificate"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() Validated TpmPublicKeyModulus successfully")

	err = certifyKey20.ValidateNameDigest()
	if err != nil {
		return nil, errors.Wrap(err, "TPM Key Name specified does not match name digest in the TCG binding certificate"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() TpmNameDigest validated successfully")
	pcaKey := (*certifyHostKeysController.CertStore)[models.CaCertTypesPrivacyCa.String()].Key
	pcaCert := (*certifyHostKeysController.CertStore)[models.CaCertTypesPrivacyCa.String()].Certificates
	certificate, err := certifyKey20.CertifyKey(&pcaCert[0], rsaPubKey, pcaKey.(*rsa.PrivateKey), commName)
	if err != nil {
		return nil, errors.Wrapf(err, "controllers/certify_host_keys_controller:generateCertificate() Error while Certifying key"), http.StatusInternalServerError
	}
	defaultLog.Infof("controllers/certify_host_keys_controller:generateCertificate() certificate created successfully")
	return certificate, nil, http.StatusCreated
}

func (certifyHostKeysController *CertifyHostKeysController) isAikCertifiedByPrivacyCA(aikCert *x509.Certificate) bool {
	defaultLog.Trace("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Leaving")

	pcaCert := (*certifyHostKeysController.CertStore)[models.CaCertTypesPrivacyCa.String()].Certificates
	pubKey, err := crypt.GetPublicKeyFromCert(&pcaCert[0])
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Could not get Public key from privacy ca certificate")
		return false
	}
	rsaPublicKey := pubKey.(*rsa.PublicKey)

	h := sha256.New()
	_, err = h.Write(aikCert.RawTBSCertificate)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Could not write certificate")
		return false
	}
	digest := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, aikCert.Signature)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Error while verifying the AIK signature against the Privacy CA")
		return false
	}

	return true
}
