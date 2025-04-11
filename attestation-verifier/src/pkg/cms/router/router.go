/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var defaultLog = log.GetDefaultLogger()

type Router struct {
	cfg *config.Configuration
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration) *mux.Router {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	router.SkipClean(true)
	defineSubRoutes(router, strings.ToLower(constants.ServiceName), cfg)
	return router
}

func defineSubRoutes(router *mux.Router, service string, cfg *config.Configuration) {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	serviceApi := "/" + service + constants.ApiVersion
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = SetVersionRoutes(subRouter)
	subRouter = SetCACertificatesRoutes(subRouter)

	subRouter = router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{cfg: cfg}
	subRouter.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.ConfigDir, cfgRouter.fnGetJwtCerts,
		time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	subRouter = SetCertificatesRoutes(subRouter, cfg)
}

// Fetch JWT certificate from AAS
//TODO: use interface to store save certificates
func (r *Router) fnGetJwtCerts() error {
	defaultLog.Trace("router/router:fnGetJwtCerts() Entering")
	defer defaultLog.Trace("router/router:fnGetJwtCerts() Leaving")

	cfg := r.cfg
	if !strings.HasSuffix(cfg.AASApiUrl, "/") {
		cfg.AASApiUrl = cfg.AASApiUrl + "/"
	}
	url := cfg.AASApiUrl + "jwt-certificates"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.RootCADirPath, "*.pem")
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not initiate certificate pool")
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing response body")
		}
	}()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not read response body")
	}
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}
