/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ta

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
)

var (
	defaultTimeout = 10 * time.Second
)

func NewNatsTAClient(natsServers []string, natsHostID string, tlsConfig *tls.Config, natsCredentials string, imaMeasureEnabled bool) (TAClient, error) {

	if len(natsServers) == 0 {
		return nil, errors.New("client/nats_client:NewNatsTAClient() At least one nats-server must be provided.")
	}

	if natsHostID == "" {
		return nil, errors.New("client/nats_client:NewNatsTAClient() The nats-host-id was not provided")
	}

	if tlsConfig == nil {
		return nil, errors.New("client/nats_client:NewNatsTAClient() TLS configuration was not provided")
	}

	if natsCredentials == "" {
		return nil, errors.New("client/nats_client:NewNatsTAClient() NATS credential file path was not provided")
	}

	client := natsTAClient{
		natsServers:       natsServers,
		natsHostID:        natsHostID,
		tlsConfig:         tlsConfig,
		natsCredentials:   natsCredentials,
		imaMeasureEnabled: imaMeasureEnabled,
	}

	return &client, nil
}

func (client *natsTAClient) newNatsConnection() (*nats.EncodedConn, error) {

	conn, err := nats.Connect(strings.Join(client.natsServers, ","),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(5*time.Second),
		nats.Timeout(10*time.Second),
		nats.Secure(client.tlsConfig),
		nats.UserCredentials(client.natsCredentials),
		nats.ErrorHandler(func(nc *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				log.WithError(err).Errorf("client/nats_client:newNatsConnection() NATS: Could not process subscription for subject %q", s.Subject)
			} else {
				log.WithError(err).Error("client/nats_client:newNatsConnection() NATS: Unknown error")
			}
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Debug("client/nats_client:newNatsConnection() NATS: Client disconnected")
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Debug("client/nats_client:newNatsConnection() NATS: Client reconnected")
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Debug("client/nats_client:newNatsConnection() NATS: Client closed")
		}))

	if err != nil {
		return nil, fmt.Errorf("Failed to create nats connection: %+v", err)
	}

	encodedConn, err := nats.NewEncodedConn(conn, "json")
	if err != nil {
		return nil, fmt.Errorf("client/nats_client:newNatsConnection() Failed to create encoded connection: %+v", err)
	}

	return encodedConn, nil
}

type natsTAClient struct {
	natsServers       []string
	natsConnection    *nats.EncodedConn
	natsHostID        string
	tlsConfig         *tls.Config
	natsCredentials   string
	imaMeasureEnabled bool
}

func (client *natsTAClient) GetHostInfo() (taModel.HostInfo, error) {
	hostInfo := taModel.HostInfo{}
	conn, err := client.newNatsConnection()
	if err != nil {
		return hostInfo, errors.Wrap(err, "client/nats_client:GetHostInfo() Error establishing connection to nats server")
	}
	defer conn.Close()

	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsHostInfoRequest), nil, &hostInfo, defaultTimeout)
	if err != nil {
		return hostInfo, errors.Wrap(err, "client/nats_client:GetHostInfo() Error getting Host Info")
	}
	return hostInfo, nil
}

func (client *natsTAClient) GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error) {
	quoteResponse := taModel.TpmQuoteResponse{}
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return quoteResponse, errors.Wrap(err, "client/nats_client:GetTPMQuote() Error decoding nonce from base64 to bytes")
	}
	quoteRequest := taModel.TpmQuoteRequest{
		Nonce:             nonceBytes,
		Pcrs:              pcrList,
		PcrBanks:          pcrBankList,
		ImaMeasureEnabled: client.imaMeasureEnabled,
	}

	conn, err := client.newNatsConnection()
	if err != nil {
		return quoteResponse, errors.Wrap(err, "client/nats_client:GetTPMQuote() Error establishing connection to nats server")
	}
	defer conn.Close()

	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsQuoteRequest), &quoteRequest, &quoteResponse, defaultTimeout)
	if err != nil {
		return quoteResponse, errors.Wrap(err, "client/nats_client:GetTPMQuote() Error getting quote")
	}
	return quoteResponse, nil
}

func (client *natsTAClient) GetAIK() ([]byte, error) {
	conn, err := client.newNatsConnection()
	if err != nil {
		return nil, errors.Wrap(err, "client/nats_client:GetAIK() Error establishing connection to nats server")
	}
	defer conn.Close()

	var aik []byte
	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsAikRequest), nil, &aik, defaultTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "client/nats_client:GetAIK() Error getting AIK")
	}
	return aik, nil
}

func (client *natsTAClient) GetBindingKeyCertificate() ([]byte, error) {
	conn, err := client.newNatsConnection()
	if err != nil {
		return nil, errors.Wrap(err, "client/nats_client:GetBindingKeyCertificate() Error establishing connection to nats server")
	}
	defer conn.Close()

	var bk []byte
	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsBkRequest), nil, &bk, defaultTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "client/nats_client:GetBindingKeyCertificate() Error getting binding key")
	}
	// NATS converts nil response received from TA to null hence explicitly returning nil response
	if string(bk) == "null" {
		return nil, nil
	}
	return bk, nil
}

func (client *natsTAClient) DeployAssetTag(hardwareUUID, tag string) error {
	var err error
	var tagWriteRequest taModel.TagWriteRequest
	tagWriteRequest.Tag, err = base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return errors.Wrap(err, "client/nats_client:DeployAssetTag() Error decoding tag from base64 to bytes")
	}
	tagWriteRequest.HardwareUUID = hardwareUUID

	conn, err := client.newNatsConnection()
	if err != nil {
		return errors.Wrap(err, "client/nats_client:DeployAssetTag() Error establishing connection to nats server")
	}
	defer conn.Close()

	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsDeployAssetTagRequest), &tagWriteRequest, &nats.Msg{}, defaultTimeout)
	if err != nil {
		return errors.Wrap(err, "client/nats_client:DeployAssetTag() Error deploying asset tag")
	}
	return nil
}

func (client *natsTAClient) DeploySoftwareManifest(manifest taModel.Manifest) error {
	conn, err := client.newNatsConnection()
	if err != nil {
		return errors.Wrap(err, "client/nats_client:DeploySoftwareManifest() Error establishing connection to nats server")
	}
	defer conn.Close()

	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsDeployManifestRequest), &manifest, &nats.Msg{}, defaultTimeout)
	if err != nil {
		return errors.Wrap(err, "client/nats_client:DeploySoftwareManifest() Error deploying software flavor")
	}
	return nil
}

func (client *natsTAClient) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	measurement := taModel.Measurement{}
	conn, err := client.newNatsConnection()
	if err != nil {
		return measurement, errors.Wrap(err, "client/nats_client:GetMeasurementFromManifest() Error establishing connection to nats server")
	}
	defer conn.Close()

	err = conn.Request(taModel.CreateSubject(client.natsHostID, taModel.NatsApplicationMeasurementRequest), &manifest, &measurement, defaultTimeout)
	if err != nil {
		return measurement, errors.Wrap(err, "client/nats_client:GetMeasurementFromManifest() Error getting measurement from TA")
	}
	return measurement, nil
}

func (client *natsTAClient) GetBaseURL() *url.URL {
	return nil
}
