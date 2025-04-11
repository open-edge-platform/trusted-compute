/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"io/ioutil"
	"net/http"
	"strings"
)

type CACertificatesController struct {
	CaAttribs map[string]constants.CaAttrib
}

//GetCACertificates is used to get the root CA certificate upon JWT validation
func (controller CACertificatesController) GetCACertificates(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Trace("resource/ca_certificates:GetCACertificates() Entering")
	defer log.Trace("resource/ca_certificates:GetCACertificates() Leaving")

	httpWriter.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	if httpRequest.Header.Get("Accept") != consts.HTTPMediaTypePemFile {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		_, err := httpWriter.Write([]byte("Accept type not supported"))
		if err != nil {
			log.WithError(err).Errorf("resource/ca_certificates:GetCACertificates() Failed to write response")
		}
		return
	}

	issuingCa := httpRequest.URL.Query().Get("issuingCa")
	if issuingCa == "" {
		issuingCa = "root"
	}
	log.Debugf("resource/ca_certificates:GetCACertificates() Requesting CA certificate for - %v", issuingCa)
	caCertificateBytes, err := getCaCert(issuingCa, controller.CaAttribs)
	if err != nil {
		log.WithError(err).Errorf("resource/ca_certificates:GetCACertificates() Cannot load Issuing CA - %v", issuingCa)
		if strings.Contains(err.Error(), "Invalid Query parameter") {
			slog.Warning(commLogMsg.InvalidInputBadParam)
			httpWriter.WriteHeader(http.StatusBadRequest)
			_, err = httpWriter.Write([]byte("Invalid Query parameter provided"))
			if err != nil {
				log.WithError(err).Errorf("resource/ca_certificates:GetCACertificates() Failed to write response")
			}
		} else {
			httpWriter.WriteHeader(http.StatusInternalServerError)
			_, err = httpWriter.Write([]byte("Cannot load Issuing CA"))
			if err != nil {
				log.WithError(err).Errorf("resource/ca_certificates:GetCACertificates() Failed to write response")
			}
		}
		return
	}
	httpWriter.Header().Set("Content-Type", consts.HTTPMediaTypePemFile)
	httpWriter.WriteHeader(http.StatusOK)
	_, err = httpWriter.Write(caCertificateBytes)
	if err != nil {
		log.WithError(err).Errorf("resource/ca_certificates:GetCACertificates() Failed to write response")
	}
	log.Infof("resource/ca_certificates:GetCACertificates() Returned requested %v CA certificate", issuingCa)
	return
}

func getCaCert(issuingCa string, CaAttribs map[string]constants.CaAttrib) ([]byte, error) {
	log.Trace("resource/ca_certificates:getCaCert() Entering")
	defer log.Trace("resource/ca_certificates:getCaCert() Leaving")

	attr := constants.GetCaAttribs(issuingCa, CaAttribs)
	if attr.CommonName == "" {
		return nil, fmt.Errorf("Invalid Query parameter issuingCa: %v", issuingCa)
	} else {
		return ioutil.ReadFile(attr.CertPath)
	}
}
