/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/vcss"

	"github.com/pkg/errors"

	stdlog "log"

	"github.com/gorilla/handlers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/auditlog"
	hostfetcher "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/host-fetcher"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hrrs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	hostconnector "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

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

	// Initialize Database
	dataStore, err := postgres.InitDatabase(&c.DB)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing Database")
	}

	// Initialize audit log
	als := postgres.NewAuditLogEntryStore(dataStore)
	alw, _ := auditlog.NewAuditLogDBWriter(als, c.AuditLog.BufferSize)

	// Load Certificates
	certStore, err := crypt.LoadCertificates(a.loadCertPathStore(), models.GetUniqueCertTypes())
	if err != nil {
		return errors.Wrap(err, "Error while loading required certificates")
	}

	// Initialize Host trust manager
	fgs := postgres.NewFlavorGroupStore(dataStore)
	hostTrustManager := initHostTrustManager(c, dataStore, fgs, certStore, alw)
	go hostTrustManager.ProcessQueue()

	// create an instance of the HRRS and start it...
	reportStore := postgres.NewReportStore(dataStore)
	reportStore.AuditLogWriter = alw
	reportRefresher, err := hrrs.NewHostReportRefresher(c.HRRS, reportStore, hostTrustManager)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing HRRS")
	}

	err = reportRefresher.Run()
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing Report Refresher")
	}

	// Initialize Host controller config
	hostControllerConfig := initHostControllerConfig(c, certStore)

	//Create an instance of VCSS and start the service
	vcenterClusterSyncer, err := vcss.NewVCenterClusterSyncer(c.VCSS, hostControllerConfig, dataStore, hostTrustManager)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing VCSS")
	}

	err = vcenterClusterSyncer.Run()
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing vCenter Cluster Syncer")
	}

	// Initialize routes
	routes, err := router.InitRoutes(c, dataStore, fgs, certStore, hostTrustManager, hostControllerConfig)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing routes")
	}

	defaultLog.Info("Starting server")
	tlsConfig := &tls.Config{
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
		TLSConfig:         tlsConfig,
		ReadTimeout:       c.Server.ReadTimeout,
		ReadHeaderTimeout: c.Server.ReadHeaderTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		MaxHeaderBytes:    c.Server.MaxHeaderBytes,
	}

	tlsCert := c.TLS.CertFile
	tlsKey := c.TLS.KeyFile
	// dispatch web server go routine
	go func() {
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

	err = reportRefresher.Stop()
	if err != nil {
		return errors.Wrap(err, "An error occurred while stopping Report Refresher")
	}

	if err := h.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func initHostControllerConfig(cfg *config.Configuration, certStore *crypt.CertificatesStore) domain.HostControllerConfig {
	defaultLog.Trace("server:initHostControllerConfig() Entering")
	defer defaultLog.Trace("server:initHostControllerConfig() Leaving")

	rootCAs := (*certStore)[models.CaCertTypesRootCa.String()]
	hcProvider := hostconnector.NewHostConnectorFactory(cfg.AASApiUrl, rootCAs.Certificates, cfg.NATS.Servers, cfg.IMAMeasureEnabled)

	hcc := domain.HostControllerConfig{
		HostConnectorProvider:          hcProvider,
		DataEncryptionKey:              getDecodedDek(cfg),
		Username:                       cfg.HVS.Username,
		Password:                       cfg.HVS.Password,
		VerifyQuoteForHostRegistration: cfg.VerifyQuoteForHostRegistration,
	}
	return hcc
}

func getDecodedDek(cfg *config.Configuration) []byte {
	dekBase64 := cfg.Dek
	if dekBase64 == "" {
		defaultLog.Warn("Data encryption key is not defined")
	}
	dek, err := base64.StdEncoding.DecodeString(dekBase64)
	if err != nil {
		defaultLog.WithError(err).Warn("Data encryption key is not base64 encoded")
	}
	return dek
}

func initHostTrustManager(cfg *config.Configuration, dataStore *postgres.DataStore, fgs domain.FlavorGroupStore, certStore *crypt.CertificatesStore, alw domain.AuditLogWriter) domain.HostTrustManager {
	defaultLog.Trace("server:InitHostTrustManager() Entering")
	defer defaultLog.Trace("server:InitHostTrustManager() Leaving")

	//Load store
	hs := postgres.NewHostStore(dataStore)
	hc := postgres.NewHostCredentialStore(dataStore, getDecodedDek(cfg))
	fs := postgres.NewFlavorStore(dataStore)
	qs := postgres.NewDBQueueStore(dataStore)
	hss := postgres.NewHostStatusStore(dataStore)
	hss.AuditLogWriter = alw
	rs := postgres.NewReportStore(dataStore)
	rs.AuditLogWriter = alw

	//Load certificates
	rootCAs := (*certStore)[models.CaCertTypesRootCa.String()]
	tagCAs := (*certStore)[models.CaCertTypesTagCa.String()]
	samlCert := (*certStore)[models.CertTypesSaml.String()]
	privacyCAs := (*certStore)[models.CaCertTypesPrivacyCa.String()]
	signingCerts := (*certStore)[models.CertTypesFlavorSigning.String()]
	rootCApool := crypt.GetCertPool(rootCAs.Certificates)
	for _, val := range signingCerts.Certificates[1:] {
		rootCApool.AddCert(&val) //Add intermediate CA
	}

	verifierCerts := verifier.VerifierCertificates{
		PrivacyCACertificates:    crypt.GetCertPool(privacyCAs.Certificates),
		AssetTagCACertificates:   crypt.GetCertPool(tagCAs.Certificates),
		FlavorSigningCertificate: &signingCerts.Certificates[0],
		FlavorCACertificates:     rootCApool,
	}
	libVerifier, _ := verifier.NewVerifier(verifierCerts)
	samlKey := samlCert.Key.(*rsa.PrivateKey)
	samlIssuerConfig := saml.IssuerConfiguration{
		IssuerName:        cfg.SAML.Issuer,
		IssuerServiceName: constants.ServiceName,
		ValiditySeconds:   cfg.SAML.ValiditySeconds,
		PrivateKey:        samlKey,
		Certificate:       &samlCert.Certificates[0],
	}

	hostQuoteTrustCache, err := lru.New(cfg.FVS.HostTrustCacheThreshold)
	if err != nil {
		defaultLog.WithError(err).Fatal("Error initializing host trust cache")
	}
	htv := domain.HostTrustVerifierConfig{
		FlavorStore:                     fs,
		FlavorGroupStore:                fgs,
		HostStore:                       hs,
		ReportStore:                     rs,
		FlavorVerifier:                  libVerifier,
		CertsStore:                      *certStore,
		SamlIssuerConfig:                samlIssuerConfig,
		SkipFlavorSignatureVerification: cfg.FVS.SkipFlavorSignatureVerification,
		HostTrustCache:                  hostQuoteTrustCache,
	}

	// Initialize Host Fetcher service
	htcFactory := hostconnector.NewHostConnectorFactory(cfg.AASApiUrl, rootCAs.Certificates, cfg.NATS.Servers, cfg.IMAMeasureEnabled)

	c := domain.HostDataFetcherConfig{
		HostConnectorProvider: htcFactory,
		HostConnectionConfig: domain.HostConnectionConfig{
			HCStore:         hc,
			ServiceUsername: cfg.HVS.Username,
			ServicePassword: cfg.HVS.Password,
		},
		RetryTimeMinutes: 5,
		HostStatusStore:  hss,
		HostStore:        hs,
		FlavorGroupStore: fgs,
		FlavorStore:      fs,
		HostTrustCache:   hostQuoteTrustCache,
	}
	_, hf, err := hostfetcher.NewService(c, cfg.FVS.NumberOfDataFetchers)
	if err != nil {
		defaultLog.WithError(err).Error("Error initializing host fetcher")
	}
	// Initialize Host Trust service
	_, htm, _ := hosttrust.NewService(domain.HostTrustMgrConfig{
		PersistStore:      qs,
		HostStore:         hs,
		HostStatusStore:   hss,
		HostFetcher:       hf,
		Verifiers:         cfg.FVS.NumberOfVerifiers,
		HostTrustVerifier: hosttrust.NewVerifier(htv),
	})

	return htm
}

func (a *App) loadCertPathStore() *crypt.CertificatesPathStore {
	// constants are used somewhere else in the repo
	// change it into the configured paths after fixing all of them
	// currently used constants:
	//     TrustedRootCACertsDir, PrivacyCAKeyFile, PrivacyCACertFile
	return &crypt.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): crypt.CertLocation{
			KeyFile:  "",
			CertPath: constants.TrustedRootCACertsDir,
		},
		models.CaCertTypesEndorsementCa.String(): crypt.CertLocation{
			KeyFile:  constants.EndorsementCAKeyFile,
			CertPath: constants.EndorsementCACertDir,
		},
		models.CaCertTypesPrivacyCa.String(): crypt.CertLocation{
			KeyFile:  constants.PrivacyCAKeyFile,
			CertPath: constants.PrivacyCACertFile,
		},
		models.CaCertTypesTagCa.String(): crypt.CertLocation{
			KeyFile:  constants.TagCAKeyFile,
			CertPath: constants.TagCACertFile,
		},
		models.CertTypesSaml.String(): crypt.CertLocation{
			KeyFile:  constants.SAMLKeyFile,
			CertPath: constants.SAMLCertFile,
		},
		models.CertTypesTls.String(): crypt.CertLocation{
			KeyFile:  constants.DefaultTLSKeyFile,
			CertPath: constants.DefaultTLSCertFile,
		},
		models.CertTypesFlavorSigning.String(): crypt.CertLocation{
			KeyFile:  constants.FlavorSigningKeyFile,
			CertPath: constants.FlavorSigningCertFile,
		},
	}
}
