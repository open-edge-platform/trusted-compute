/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/service"
	"github.com/pkg/errors"
	"os"
	"os/signal"
	"os/user"
	"syscall"
)

func (a *App) startServer() error {
	log.Trace("server:startServer() Entering")
	defer log.Trace("server:startServer() Leaving")

	currentUser, _ := user.Current()

	// tagent container is run as root user, skip user comparison when run as a container
	if !utils.IsContainerEnv() {
		if currentUser.Username != constants.TagentUserName {
			return errors.Errorf("'tagent startWebService' must be run as the 'tagent' user, not  user '%s'\n", currentUser.Username)
		}
	}

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}
	// initialize log
	if err := a.configureLogs(c.Logging.EnableStdout, true); err != nil {
		return err
	}

	serviceParameters := service.ServiceParameters{
		Mode: a.config.Mode,
		Web: service.WebParameters{
			ServerConfig:              a.config.Server,
			TLSCertFilePath:           constants.TLSCertFilePath,
			TLSKeyFilePath:            constants.TLSKeyFilePath,
			TrustedJWTSigningCertsDir: constants.TrustedJWTSigningCertsDir,
			TrustedCaCertsDir:         constants.TrustedCaCertsDir,
		},
		Nats: service.NatsParameters{
			NatsService:       a.config.Nats,
			CredentialFile:    constants.NatsCredentials,
			TrustedCaCertsDir: constants.TrustedCaCertsDir,
		},
		RequestHandler: common.NewRequestHandler(c),
	}

	trustAgentService, err := service.NewTrustAgentService(&serviceParameters)
	if err != nil {
		log.WithError(err).Info("Failed to create service")
		os.Exit(1)
	}

	// Setup signal handlers to terminate service
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	err = trustAgentService.Start()
	if err != nil {
		log.WithError(err).Info("Failed to start service")
		stop <- syscall.SIGTERM
	}

	err = sendAsyncReportRequest(c)
	if err != nil {
		asyncReportCreateRetry(c)
	}

	// wait till the termination signal is received
	<-stop

	if err := trustAgentService.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to shutdown service: %v\n", err)
		log.WithError(err).Info("Failed to shutdown service")
		os.Exit(1)
	}

	return nil
}
