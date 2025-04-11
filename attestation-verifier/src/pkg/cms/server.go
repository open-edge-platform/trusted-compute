/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"

	stdlog "log"

	"github.com/gorilla/handlers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	"github.com/pkg/errors"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
)

var defaultLog = commLog.GetDefaultLogger()

func (a *App) startServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, true); err != nil {
		return err
	}

	// Initialize routes
	routes := router.InitRoutes(c)
	loggerMiddleware := middleware.LogWriterMiddleware{a.logWriter()}
	routes.Use(loggerMiddleware.WriteDurationLog())
	tlsconfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr: fmt.Sprintf(":%d", c.Server.Port),
		Handler: handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(
			true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), routes)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.Server.ReadTimeout,
		ReadHeaderTimeout: c.Server.ReadHeaderTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		MaxHeaderBytes:    c.Server.MaxHeaderBytes,
	}

	tlsCert := constants.TLSCertPath
	tlsKey := constants.TLSKeyPath

	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			if err != http.ErrServerClosed {
				defaultLog.WithError(err).Fatal("Failed to start HTTPS server")
			}
			stop <- syscall.SIGTERM
		}
	}()

	slog.Info(message.ServiceStart)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		return errors.Wrap(err, "app:startServer() Failed to gracefully shutdown webserver")
	}
	slog.Info(message.ServiceStop)
	return nil
}

func (a *App) loadCertPathStore() *crypt.CertificatesPathStore {
	return &crypt.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): crypt.CertLocation{
			KeyFile:  "",
			CertPath: constants.RootCADirPath,
		},
		models.CertTypesTls.String(): crypt.CertLocation{
			KeyFile:  constants.TLSKeyPath,
			CertPath: constants.TLSCertPath,
		},
	}
}
