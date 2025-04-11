/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/auth"
	commContext "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"strings"
)

func ErrorHandler(eh middleware.EndpointHandler) http.HandlerFunc {
	log.Trace("router/handlers:errorHandler() Entering")
	defer log.Trace("router/handlers:errorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Errorf("Panic occurred: %+v\n%s", err, string(debug.Stack()))
				http.Error(w, "Unknown Error", http.StatusInternalServerError)
			}
		}()

		if err := eh(w, r); err != nil {
			if strings.TrimSpace(strings.ToLower(err.Error())) == "record not found" {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *common.EndpointError:
				http.Error(w, t.Message, t.StatusCode)
			case PrivilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

type PrivilegeError struct {
	StatusCode int
	Message    string
}

func (e PrivilegeError) Error() string {
	log.Trace("router/router:Error() Entering")
	defer log.Trace("router/router:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func fnGetJwtCerts() error {
	log.Trace("router/handlers:fnGetJwtCerts() Entering")
	defer log.Trace("router/handlers:fnGetJwtCerts() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		fmt.Printf("ERROR: %+v\n", err)
		return nil
	}

	jwtUrl := clients.ResolvePath(cfg.Aas.BaseURL, "jwt-certificates")
	req, _ := http.NewRequest(http.MethodGet, jwtUrl, nil)
	req.Header.Add("accept", "application/x-pem-file")
	secLog.Debugf("router/handlers::fnGetJwtCerts() Connecting to AAS Endpoint %s", jwtUrl)

	caCerts, err := crypt.GetCertsFromDir(constants.TrustedCaCertsDir)
	if err != nil {
		log.WithError(err).Errorf("router/handlers::fnGetJwtCerts() Error while getting certs from %s", constants.TrustedCaCertsDir)
		return errors.Wrap(err, "router/handlers::fnGetJwtCerts() Error while getting certs from %s")
	}

	hc, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		return errors.Wrap(err, "router/handlers:fnGetJwtCerts() Error setting up HTTP client")
	}

	res, err := hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "router/handlers:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "router/handlers:fnGetJwtCerts() Error while reading response body")
	}

	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/handlers:fnGetJwtCerts() Error while saving certificate")
	}

	return nil
}

// RequiresPermission checks the JWT in the request for the required access permissions
func RequiresPermission(eh middleware.EndpointHandler, permissionNames []string) middleware.EndpointHandler {
	log.Trace("router/handlers:requiresPermission() Entering")
	defer log.Trace("router/handlers:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := commContext.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			_, writeErr := w.Write([]byte("Could not get user roles from http context"))
			if writeErr != nil {
				log.WithError(writeErr).Warn("router/handlers:requiresPermission() Error while writing response")
			}
			secLog.Errorf("router/handlers:requiresPermission() %s Roles: %v | Context: %v", message.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "router/handlers:requiresPermission() Could not get user roles from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.TAServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("router/handlers:requiresPermission() %s Insufficient privileges to access %s", message.UnauthorizedAccess, r.RequestURI)
			return &PrivilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		secLog.Debugf("router/handlers:requiresPermission() %s - %s", message.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}
