/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var routes *mux.Router
var caCertificatesController CACertificatesController
var payloadMock = []byte{}
var res *httptest.ResponseRecorder
var pathMock string
var pathCertMock map[string]constants.CaAttrib

func setupenv(t *testing.T) func() {
	pathMock, pathCertMock = CreateTestFilePath()
	CreateRootCa(pathMock, pathCertMock)
	caCertificatesController = CACertificatesController{CaAttribs: pathCertMock}
	routes = mux.NewRouter()
	res = httptest.NewRecorder()
	return func() {
		routes = nil
		DeleteTestFilePath(pathMock)
	}
}

func TestIncorrectHeaderOfTypeAccept(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	routes.HandleFunc("/ca-certificates", caCertificatesController.GetCACertificates).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/ca-certificates", bytes.NewBuffer(payloadMock))
	req.Header.Set("Accept", consts.HTTPMediaTypePlain)
	routes.ServeHTTP(res, req)
	if !(res.Code == http.StatusNotAcceptable) {
		t.Error("incorrect accept type provided in header")
	}
}

func TestNoParamsGiven(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	routes.HandleFunc("/ca-certificates", caCertificatesController.GetCACertificates).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/ca-certificates", bytes.NewBuffer(payloadMock))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	routes.ServeHTTP(res, req)
	if !(res.Code == http.StatusOK) {
		t.Error("No query params given. Hence should take efault value as root and return cert")
	}
}

func TestBadQueryParam(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	routes.HandleFunc("/ca-certificates", caCertificatesController.GetCACertificates).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/ca-certificates?issuingCa=notapplicable", bytes.NewBuffer(payloadMock))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	routes.ServeHTTP(res, req)
	if !(res.Code == http.StatusBadRequest) {
		t.Error("Invalid query param given in issuingca")
	}
}

func TestShouldReturnRoot(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	routes.HandleFunc("/ca-certificates", caCertificatesController.GetCACertificates).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/ca-certificates?issuingCa=root", bytes.NewBuffer(payloadMock))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	routes.ServeHTTP(res, req)
	if !(res.Code == http.StatusOK) {
		t.Error("Should return rootca cert and status as ok")
	}
}

func TestShouldFailAsDirNotFound(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	routes.HandleFunc("/ca-certificates", caCertificatesController.GetCACertificates).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/ca-certificates?issuingCa=TLS", bytes.NewBuffer(payloadMock))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	routes.ServeHTTP(res, req)
	if !(res.Code == http.StatusInternalServerError) {
		t.Error("Tls certificate directory not found hence should throw an error")
	}
}

func TestErrorIngetCaCert(t *testing.T) {
	teardown := setupenv(t)
	defer teardown()
	_, err := getCaCert("test", pathCertMock)
	assert.Error(t, err)
}
