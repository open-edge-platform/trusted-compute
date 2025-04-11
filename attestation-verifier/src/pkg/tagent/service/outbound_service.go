/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/version"
	"golang.org/x/net/proxy"

	"crypto/tls"
	"crypto/x509"
	"runtime/debug"
	"strings"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"

	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"

	"github.com/nats-io/nats.go"
)

func newOutboundService(natsParameters *NatsParameters, handler common.RequestHandler, platformInfoFilePath string) (TrustAgentService, error) {

	if natsParameters.HostID == "" {
		return nil, errors.New("The configuration does not have a 'nats-host-id'.")
	}

	return &trustAgentOutboundService{
		handler:              handler,
		natsParameters:       *natsParameters,
		platformInfoFilePath: platformInfoFilePath,
	}, nil
}

type trustAgentOutboundService struct {
	natsConnection       *nats.EncodedConn
	handler              common.RequestHandler
	natsParameters       NatsParameters
	platformInfoFilePath string
}

func (subscriber *trustAgentOutboundService) Start() error {

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := cos.GetDirFileContents(subscriber.natsParameters.TrustedCaCertsDir, "*.pem")
	if err != nil {
		log.WithError(err).Errorf("Failed to append %q to RootCAs", subscriber.natsParameters.TrustedCaCertsDir)
	}

	for _, rootCACert := range certs {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			log.Debug("No certs appended, using system certs only")
		}
	}

	tlsConfig := tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	conn, err := nats.Connect(strings.Join(subscriber.natsParameters.Servers, ","),
		nats.Name(subscriber.natsParameters.HostID),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(5*time.Second),
		nats.Timeout(10*time.Second),
		nats.Secure(&tlsConfig),
		nats.UserCredentials(subscriber.natsParameters.CredentialFile),
		nats.DisconnectErrHandler(func(conn *nats.Conn, err error) {
			log.WithError(err).Debugf("NATs client disconnected [%s]", conn.Opts.Name)
		}),
		nats.ReconnectHandler(func(conn *nats.Conn) {
			log.Debugf("NATs client reconnected [%s] to %q", conn.Opts.Name, conn.ConnectedAddr())
		}),
		nats.ClosedHandler(func(conn *nats.Conn) {
			log.Debugf("NATs client closed [%s]", conn.Opts.Name)
		}),
		nats.ErrorHandler(func(conn *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				log.WithError(err).Errorf("NATs error processing subscription [%s]: %q", conn.Opts.Name, s.Subject)
			} else {
				log.WithError(err).Error("NATs error")
			}
		}),
		nats.SetCustomDialer(proxy.FromEnvironment()),
	)

	if err != nil {
		return errors.Wrapf(err, "NATs failed to connect to url %q", subscriber.natsParameters.Servers)
	}

	subscriber.natsConnection, err = nats.NewEncodedConn(conn, "json")
	if err != nil {
		log.WithError(err).Error("NATs failed to create encoded connection")
	}

	// subscribe to quote-request messages
	quoteSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsQuoteRequest)
	_, err = subscriber.natsConnection.Subscribe(quoteSubject, func(subject string, reply string,
		quoteRequest *taModel.TpmQuoteRequest) error {
		defer recoverFunc()

		quoteResponse, err := subscriber.handler.GetTpmQuote(quoteRequest, constants.AikCert, constants.MeasureLogFilePath, constants.RamfsDir)
		if err != nil {
			log.WithError(err).Error("Failed to handle quote-request")
			return err
		}

		return subscriber.natsConnection.Publish(reply, quoteResponse)
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to quote-request messages")
	}

	//subscribe to host-info request messages
	hostInfoSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsHostInfoRequest)
	_, err = subscriber.natsConnection.Subscribe(hostInfoSubject, func(m *nats.Msg) error {
		defer recoverFunc()

		hostInfo, err := subscriber.handler.GetHostInfo(subscriber.platformInfoFilePath)
		if err != nil {
			log.WithError(err).Error("Failed to handle host-info")
			return err
		}

		return subscriber.natsConnection.Publish(m.Reply, hostInfo)
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to host-info messages")
	}

	// subscribe to aik request messages
	aikSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsAikRequest)
	_, err = subscriber.natsConnection.Subscribe(aikSubject, func(m *nats.Msg) error {
		defer recoverFunc()

		aik, err := subscriber.handler.GetAikDerBytes(constants.AikCert)
		if err != nil {
			log.WithError(err).Error("Failed to handle aik-request")
			return err
		}

		return subscriber.natsConnection.Publish(m.Reply, aik)
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to aik-request messages")
	}

	// subscribe to deploy asset tag request messages
	deployTagSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsDeployAssetTagRequest)
	_, err = subscriber.natsConnection.Subscribe(deployTagSubject, func(subject string, reply string, tagWriteRequest *taModel.TagWriteRequest) error {
		defer recoverFunc()

		err := subscriber.handler.DeployAssetTag(tagWriteRequest)
		if err != nil {
			log.WithError(err).Error("Failed to handle deploy-asset-tag")
			return err
		}

		return subscriber.natsConnection.Publish(reply, "")
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to deploy-asset-tag messages")
	}

	// subscribe to binding key request messages
	bkSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsBkRequest)
	_, err = subscriber.natsConnection.Subscribe(bkSubject, func(m *nats.Msg) error {
		defer recoverFunc()

		bk, err := subscriber.handler.GetBindingCertificateDerBytes(constants.BindingKeyCertificatePath)
		if err != nil {
			log.WithError(err).Error("Failed to handle get-binding-certificate")
			return subscriber.natsConnection.Publish(m.Reply, nil)
		}

		return subscriber.natsConnection.Publish(m.Reply, bk)
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to binding-key-request messages")
	}

	// subscribe to deploy manifest request messages
	deployManifestSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsDeployManifestRequest)
	_, err = subscriber.natsConnection.Subscribe(deployManifestSubject, func(subject string, reply string, manifest *taModel.Manifest) error {
		defer recoverFunc()

		err = subscriber.handler.DeploySoftwareManifest(manifest, constants.VarDir)
		if err != nil {
			log.WithError(err).Error("Failed to handle deploy-manifest")
			return err
		}

		return subscriber.natsConnection.Publish(reply, "")
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to deploy-manifest messages")
	}

	// subscribe to application measurement request messages
	applicationMeasurementSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsApplicationMeasurementRequest)
	_, err = subscriber.natsConnection.Subscribe(applicationMeasurementSubject, func(subject string, reply string, manifest *taModel.Manifest) error {
		defer recoverFunc()

		measurement, err := subscriber.handler.GetApplicationMeasurement(manifest, constants.TBootXmMeasurePath, constants.LogDir)
		if err != nil {
			log.WithError(err).Error("Failed to handle application-measurement-request")
			return err
		}

		return subscriber.natsConnection.Publish(reply, measurement)
	})
	if err != nil {
		return err
	}

	// subscribe to version requests
	versionSubject := taModel.CreateSubject(subscriber.natsParameters.HostID, taModel.NatsVersionRequest)
	_, err = subscriber.natsConnection.Subscribe(versionSubject, func(m *nats.Msg) error {
		defer recoverFunc()

		return subscriber.natsConnection.Publish(m.Reply, version.GetVersion())
	})
	if err != nil {
		return errors.Wrapf(err, "NATs client failed to create subscription to version messages")
	}

	if conn.IsConnected() {
		log.Infof("Outbound Trust-Agent %q connected to %q", subscriber.natsParameters.HostID, subscriber.natsConnection.Conn.ConnectedAddr())
	}
	return nil
}

func (subscriber *trustAgentOutboundService) Stop() error {
	subscriber.natsConnection.Close()
	return nil
}

func recoverFunc() {
	if err := recover(); err != nil {
		log.Errorf("Panic occurred: %+v\n%s", err, string(debug.Stack()))
	}
}
