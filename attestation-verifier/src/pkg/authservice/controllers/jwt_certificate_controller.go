/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"io/ioutil"
	"net/http"
	"regexp"

	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

type JwtCertificateController struct {
	TokenSignCertFile string
}

var (
	re = regexp.MustCompile(`\r?\n`)
)

func (controller JwtCertificateController) GetJwtCertificate(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to getJwtCertificate")
	defer defaultLog.Trace("getJwtCertificate return")

	tokenCertificate, err := ioutil.ReadFile(controller.TokenSignCertFile)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	err = validation.ValidatePemEncodedKey(re.ReplaceAllString(string(tokenCertificate), ""))

	if err != nil {
		secLog.Errorf(commLogMsg.UnauthorizedAccess, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Invalid jwt certificate"}
	}
	secLog.Info(commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(tokenCertificate), http.StatusOK, nil
}
