/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"fmt"
	jwtauth "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/jwt"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	clog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

var jwtVerifier jwtauth.Verifier
var jwtCertDownloadAttempted bool
var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func InitJwtVerifier(signingCertsDir, trustedCAsDir string, cacheTime time.Duration) (jwtauth.Verifier, error) {

	certPems, err := cos.GetDirFileContents(signingCertsDir, "*.pem")

	rootPems, err := cos.GetDirFileContents(trustedCAsDir, "*.pem")

	jwtVerifier, err = jwtauth.NewVerifier(certPems, rootPems, cacheTime)

	return jwtVerifier, err
}

func retrieveAndSaveTrustedJwtSigningCerts() error {
	if jwtCertDownloadAttempted {
		return fmt.Errorf("already attempted to download JWT signing certificates. Will not attempt again")
	}
	// todo. this function will make https requests and save files
	// to the directory where we keep trusted certificates

	jwtCertDownloadAttempted = true
	return nil
}

type RetrieveJwtCertFn func() error

func NewTokenAuth(signingCertsDir, trustedCAsDir string, fnGetJwtCerts RetrieveJwtCertFn, cacheTime time.Duration) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Trace("Common/Middleware/NewTokenAuth() - Entering");
			defer log.Trace("Common/Middleware/NewTokenAuth() - Leaving");

			// pull up the bearer token.

			splitAuthHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(splitAuthHeader) <= 1 {
				log.Error("no bearer token provided for authorization")
				w.WriteHeader(http.StatusUnauthorized)
				slog.Warningf("%s: Invalid token, requested from %s: ", commLogMsg.AuthenticationFailed, r.RemoteAddr)
				return
			}

			// the second item in the slice should be the jwtToken. let try to validate
			claims := ct.AuthClaims{}
			var token *jwtauth.Token
			var err error

			// There are two scenarios when we retry the ValidateTokenAndClaims.
			//     1. The cached verifier has expired - could be because the certificate we are using has just expired
			//        or the time has reached when we want to look at the CRL list to make sure the certificate is still
			//        valid.
			//        Error : VerifierExpiredError
			//     2. There are no valid certificates (maybe all are expired) and we need to call the function that retrieves
			//        a new certificate. initJwtVerifier takes care of this scenario.

			for needInit, retryNeeded, looped := jwtVerifier == nil, false, false; retryNeeded || !looped; looped = true {

				if needInit || retryNeeded {
					if _, initErr := InitJwtVerifier(signingCertsDir, trustedCAsDir, cacheTime); initErr != nil {
						log.WithError(initErr).Error("attempt to initialize jwt verifier failed")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					needInit = false
				}
				retryNeeded = false
				token, err = jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(splitAuthHeader[1]), &claims)
				if err != nil && !looped {
					switch err.(type) {
					case *jwtauth.MatchingCertNotFoundError, *jwtauth.MatchingCertJustExpired:
						err = fnGetJwtCerts()
						if err != nil {
							log.WithError(err).Error("failed to get jwt certificate")
						}
						retryNeeded = true
					case *jwtauth.VerifierExpiredError:
						retryNeeded = true
					}

				}

			}

			if err != nil {
				// this is a validation failure. Let us log the message and return unauthorized
				log.WithError(err).Error("token validation Failure")
				w.WriteHeader(http.StatusUnauthorized)
				slog.Warningf("%s: Invalid token, requested from %s: ", commLogMsg.AuthenticationFailed, r.RemoteAddr)
				return
			}

			r = context.SetUserRoles(r, claims.Roles)
			r = context.SetUserPermissions(r, claims.Permissions)
			r = context.SetTokenSubject(r, token.GetSubject())
			next.ServeHTTP(w, r)
		})
	}
}
