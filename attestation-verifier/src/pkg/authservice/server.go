/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package authservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	comm "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	jwtauth "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/jwt"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) initJwtTokenFactory() (*jwtauth.JwtFactory, error) {

	defaultLog.Trace("call to initJwtTokenFactory")
	defer defaultLog.Trace("initJwtTokenFactory return")

	// retrieve the private key from file
	privKeyDer, err := crypt.GetPKCS8PrivKeyDerFromFile(constants.TokenSignKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Could not get private key - error : %v", err)
	}

	// retrieve the signing key certificate used to create the file
	cfg := a.configuration()
	var certPemBytes []byte
	if cfg.JWT.IncludeKid {
		certPemBytes, err = ioutil.ReadFile(constants.TokenSignCertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read JWT signing certificate file - error : %v", err)
		}
	}

	return jwtauth.NewTokenFactory(privKeyDer,
		cfg.JWT.IncludeKid, certPemBytes,
		"AAS JWT Issuer",
		time.Duration(cfg.JWT.TokenDurationMins)*time.Minute)
}

func (a *App) startServer() error {
	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	// initialize defender
	comm.InitDefender(c.AuthDefender.MaxAttempts, c.AuthDefender.IntervalMins, c.AuthDefender.LockoutDurationMins)

	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, true); err != nil {
		return err
	}

	defaultLog.Info("Starting server")

	// Initialize Database
	dataStore, err := postgres.InitDatabase(&c.DB)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing Database")
	}

	jwtFactory, err := a.initJwtTokenFactory()
	if err != nil {
		defaultLog.WithError(err).Error("Failed to initialize JWT Token factory")
		return err
	}

	// Initialize routes
	routes := router.InitRoutes(c, dataStore, jwtFactory)
	loggerMiddleware := middleware.LogWriterMiddleware{a.logWriter()}
	routes.Use(loggerMiddleware.WriteDurationLog())
	// ISECL-8715 - Prevent potential open redirects to external URLs
	routes.SkipClean(true)

	tlsconfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Server.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), routes)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.Server.ReadTimeout,
		ReadHeaderTimeout: c.Server.ReadHeaderTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		MaxHeaderBytes:    c.Server.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		tlsCert := c.TLS.CertFile
		tlsKey := c.TLS.KeyFile
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			if err != http.ErrServerClosed {
				defaultLog.WithError(err).Fatal("Failed to start HTTPS server")
			}
			stop <- syscall.SIGTERM
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}
