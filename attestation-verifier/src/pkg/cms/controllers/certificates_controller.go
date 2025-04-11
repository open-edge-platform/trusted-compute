/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/auth"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	v "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type CertificatesController struct {
	Config    *config.Configuration
	CaAttribs map[string]constants.CaAttrib
	SerialNo  string
}

//GetCertificates is used to get the JWT Signing/TLS certificate upon JWT validation
func (controller CertificatesController) GetCertificates(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Trace("resource/certificates:GetCertificates() Entering")
	defer log.Trace("resource/certificates:GetCertificates() Leaving")

	if httpRequest.Header.Get("Content-Type") != consts.HTTPMediaTypePemFile {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		_, err := httpWriter.Write([]byte("Content type not supported"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	if httpRequest.Header.Get("Accept") != consts.HTTPMediaTypePemFile {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		_, err := httpWriter.Write([]byte("Accept type not supported"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	privileges, err := context.GetUserRoles(httpRequest)
	if err != nil {
		slog.WithError(err).Warn("resource/certificates:GetCertificates() Failed to read roles and permissions")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Could not get user roles from http context"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	ctxMap, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges,
		[]ct.RoleInfo{{Service: constants.ServiceName, Name: constants.CertApproverGroupName}},
		true)
	if !foundRole {
		slog.Warning(commLogMsg.UnauthorizedAccess)
		httpWriter.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: this is a POST.. we should not be having Query parameters here. If we need to distinguish the type of
	// certificate requested, this should be part of the path and not a query parameter.
	certType := httpRequest.URL.Query().Get("certType")
	if certType == "" {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.Error("resource/certificates:GetCertificates() Query parameter certType missing")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Query parameter certType missing"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	certTypeVal := []string{certType}
	if validateErr := v.ValidateStrings(certTypeVal); validateErr != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.Error("resource/certificates:GetCertificates() Query parameter certType is in invalid format")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Query parameter certType is in invalid format"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	requestBodyBytes, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Could not read http request body")
		_, err = httpWriter.Write([]byte("Cannot read http request body"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	pemBlock, _ := pem.Decode(requestBodyBytes)
	if pemBlock == nil || !strings.Contains(pemBlock.Type, "CERTIFICATE REQUEST") {
		slog.Warning(commLogMsg.InvalidInputBadEncoding)
		log.WithError(err).Error("resource/certificates:GetCertificates() Failed to decode pem block containing certificate")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Failed to decode pem"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Invalid CSR provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Invalid CSR provided"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	err = clientCSR.CheckSignature()
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() CSR signature does not match")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Invalid CSR provided"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	err = validation.ValidateCertificateRequest(controller.Config, clientCSR, certType, ctxMap)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Invalid CSR provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Invalid CSR provided"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	log.Debug("resource/certificates:GetCertificates() Received valid CSR")

	serialNumber, err := utils.GetNextSerialNumber(controller.SerialNo)
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Failed to read next Serial Number")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Failed to read next Serial Number"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: clientCSR.Subject.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// TODO: is the certificate requested is not a TLS certificate, we need to make sure that there is no SAN list
	// in the CSR and that the the CN is not in the form of a domain name/ IP address

	var issuingCa string
	log.Debugf("resource/certificates:GetCertificates() Processing CSR with cert type - %v", certType)
	if strings.EqualFold(certType, "TLS") {
		issuingCa = constants.Tls
		clientCRTTemplate.DNSNames = clientCSR.DNSNames
		clientCRTTemplate.IPAddresses = clientCSR.IPAddresses

		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	} else if strings.EqualFold(certType, "Flavor-Signing") || strings.EqualFold(certType, "JWT-Signing") || strings.EqualFold(certType, "Signing") {
		issuingCa = constants.Signing
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	} else if strings.EqualFold(certType, "TLS-Client") {
		issuingCa = constants.TlsClient
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	} else {
		log.Errorf("Invalid certType provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		_, err = httpWriter.Write([]byte("Invalid certType provided"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	caAttr := constants.GetCaAttribs(issuingCa, controller.CaAttribs)

	caCert, caPrivKey, err := crypt.LoadX509CertAndPrivateKey(caAttr.CertPath, caAttr.KeyPath)
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Could not load Issuing CA")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Cannot load Issuing CA"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCert, clientCSR.PublicKey, caPrivKey)
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Cannot create certificate from CSR")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Cannot create certificate"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}

	httpWriter.Header().Add("Content-Type", consts.HTTPMediaTypePemFile)
	httpWriter.WriteHeader(http.StatusOK)
	// encode the certificate first
	err = pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to encode certificate")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Cannot encode issued certificate"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	// include the issuing CA as well since clients would need the entire chain minus the root.
	err = pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err != nil {
		log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to encode certificate")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		_, err = httpWriter.Write([]byte("Cannot encode Issuing CA"))
		if err != nil {
			log.WithError(err).Errorf("resource/certificates:GetCertificates() Failed to write response")
		}
		return
	}
	log.Infof("resource/certificates:GetCertificates() Issued certificate for requested CSR with CN - %v", clientCSR.Subject.String())
	return
}
