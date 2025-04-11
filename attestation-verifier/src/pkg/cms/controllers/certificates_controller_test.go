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
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var router *mux.Router
var w *httptest.ResponseRecorder
var certificatesController CertificatesController

var payload = mockCertificate("CERTIFICATE REQUEST", false, false)
var role1 = ct.RoleInfo{"CMS", "CertApprover", "CN=AAS JWT Signing Certificate;CERTTYPE=JWT-Signing"}
var role2 = ct.RoleInfo{"CMS", "CertApprover", "CN=AAS TLS Certificate;SAN=10.10.10.10,10.10.10.10;CERTTYPE=TLS"}
var roles = []ct.RoleInfo{role1, role2}
var claims = ct.AuthClaims{
	Roles:       roles,
	Permissions: []ct.PermissionInfo{},
}
var mockPath string
var mockPathCert map[string]constants.CaAttrib

func setup(t *testing.T) func() {
	mockPath, mockPathCert = CreateTestFilePath()
	CreateIntermediateCa(mockPath, mockPathCert)
	certificatesController = CertificatesController{CaAttribs: mockPathCert, SerialNo: mockPath + MockSerialNo}
	router = mux.NewRouter()
	w = httptest.NewRecorder()
	return func() {
		DeleteTestFilePath(mockPath)
		router = nil
	}
}

func TestIncorrectContentType(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePlain)
	req.Header.Set("Content-Type", "")
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusNotAcceptable) {
		t.Error("incorrect Content type provided in header")
	}
}

func TestIncorrectAcceptType(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePlain)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusNotAcceptable) {
		t.Error("incorrect Accept type provided in header")
	}
}

func TestAuthNotSet(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusInternalServerError) {
		t.Error("Auth token not provided")
	}
}

func TestUnAuthorizedToken(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	claim := ct.AuthClaims{Roles: []ct.RoleInfo{}, Permissions: []ct.PermissionInfo{}}
	req = context.SetUserRoles(req, claim.Roles)
	req = context.SetUserPermissions(req, claim.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusUnauthorized) {
		t.Error("Unauthorised request")
	}
}

func TestNoCertTypeProvided(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("No cert type provided in params")
	}
}

func TestInvalidCertTypeProvided(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing@", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Invalid cert type provided in params")
	}
}

func TestNoCertGivenInReqBody(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	payloadMock := []byte{}
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payloadMock)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("No cert given in the request body")
	}
}

func TestInvalidCsr(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	payloadmock := mockCertificate("CERTIFICATE REQU", false, false)
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payloadmock)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Invalid csr cert provided in body")
	}
}

func TestInvalidParseCert(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	payloadmock := mockCertificate("CERTIFICATE REQUEST", true, false)
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payloadmock)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Invalid cert provided in the body")
	}
}

func TestParseCertDiffAlgo(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	payloadmock := mockCertificate("CERTIFICATE REQUEST", false, true)
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payloadmock)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Cert provided in the body is signed with a different algo")
	}
}

func TestParseCertWithInvalidRole(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=TLS", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	mockRole1 := ct.RoleInfo{"CMS", "CertApprover", "CN=AAS JWT;CERTTYPE=JWT-Signing"}
	mockRole2 := ct.RoleInfo{"CMS", "CertApprover", "CN=AAS TLS Certificate;SAN=localhost,10.34.653.21;CERTTYPE=TLS"}
	mockRoles := []ct.RoleInfo{mockRole1, mockRole2}
	mockClaims := ct.AuthClaims{
		Roles:       mockRoles,
		Permissions: []ct.PermissionInfo{},
	}
	req = context.SetUserRoles(req, mockClaims.Roles)
	req = context.SetUserPermissions(req, mockClaims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Invalid San ip provided in the mock roles")
	}
}

func TestIncorrectCertTypeProvided(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=hello", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusBadRequest) {
		t.Error("Invalid cert type provided in the query")
	}
}

func TestUnabletoGetIssuingCertFromFile(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	os.Remove(constants.GetCaAttribs("Signing", mockPathCert).CertPath)
	os.Remove(constants.GetCaAttribs("Signing", mockPathCert).KeyPath)
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusInternalServerError) {
		t.Error("Signing cert file not available. Hence should throw error")
	}
}

func TestIncorrectSigningCertProvided(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	os.Remove(constants.GetCaAttribs("Signing", mockPathCert).CertPath)
	fcert, _ := os.OpenFile(constants.GetCaAttribs("Signing", mockPathCert).CertPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	fcert.WriteString("test")
	fcert.Close()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusInternalServerError) {
		t.Error("Invalid signing cert provided in the jwt-signing.pem file")
	}
}

func TestGetIssuingCertSigning(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=JWT-Signing", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusOK) {
		t.Error("Certificate with type signing should be created")
	}
}

func TestGetIssuingCertTLS(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=TLS", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusOK) {
		t.Error("Certificate with type tls should be created")
	}
}

func TestGetIssuingCertTLSClient(t *testing.T) {
	teardown := setup(t)
	defer teardown()
	router.HandleFunc("/certificates", certificatesController.GetCertificates).Methods(http.MethodPost)
	req, _ := http.NewRequest(http.MethodPost, "/certificates?certType=TLS-Client", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Accept", consts.HTTPMediaTypePemFile)
	req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
	req = context.SetUserRoles(req, claims.Roles)
	req = context.SetUserPermissions(req, claims.Permissions)
	router.ServeHTTP(w, req)
	if !(w.Code == http.StatusOK) {
		t.Error("Certificate with type tls-client should be created")
	}
}
