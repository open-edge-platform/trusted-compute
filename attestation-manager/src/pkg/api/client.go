/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	// pb "attestation-manager/attestationstatusmgr"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	pb "github.com/open-edge-platform/infra-managers/attestationstatus/pkg/api/attestmgr/v1"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	defaultName = "world - AM"
	connTimeout = 20 * time.Second
)

func GetAuthConfig(ctx context.Context, caCertPath string, optionalCert *x509.Certificate) (*tls.Config, error) {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system CA certs: %v", err)
	}

	// Load CA certificate
	file, err := os.OpenFile(caCertPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open CA certificate file '%s': %w", caCertPath, err)
	}
	defer file.Close()

	caCert, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from path '%s': %w", caCertPath, err)
	}

	// Debugging: Log the first few lines of the CA certificate
	logging.Debug("CA Certificate Content: ", string(caCert[:min(len(caCert), 100)]))

	// Validate CA certificate format
	if len(caCert) == 0 {
		return nil, fmt.Errorf("CA certificate file '%s' is empty", caCertPath)
	}

	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate from path '%s': invalid certificate format", caCertPath)
	}

	if optionalCert != nil {
		caCertPool.AddCert(optionalCert)
	}

	return &tls.Config{
		RootCAs:    caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
		},
	}, nil
}

func GetAuthContext(ctx context.Context, tokenPath string) context.Context {
	file, err := os.OpenFile(tokenPath, os.O_RDONLY, 0)
	if err != nil {
		logging.Error("Failed to open token file: %v", err)
		return ctx
	}
	defer file.Close()

	tBytes, err := io.ReadAll(file)
	if err != nil {
		logging.Error("Failed to read token file: %v", err)
		return ctx
	}
	tString := fmt.Sprintf("Bearer %s", strings.TrimSpace(string(tBytes)))
	header := metadata.New(map[string]string{"authorization": tString})

	return metadata.NewOutgoingContext(ctx, header)
}

// UpdateNodeAttestationStatus connects to the server and updates the node attestation status.
func UpdateNodeAttestationStatus(cfg *constants.Config, status pb.AttestationStatus, hwUUID string, attestationStatusDetail string) (string, error) {

	caCertPath := cfg.OrchestratorCertPath
	jwtTokenPath := cfg.NodeAgentCertPath
	logging.Info("CacertPath and jwtTokenPath: ", caCertPath, jwtTokenPath)

	var addr string
	if cfg.AttestationManagerServerAddress == "" || strings.TrimSpace(cfg.AttestationManagerServerAddress) == "" {
		// Extract the address from the JWT token
		// This is a workaround for the case when the address is not provided in the config file
		// and needs to be extracted from the JWT token.
		logging.Info("AttestationManagerServerAddress is empty, extracting from JWT token")
		addr = extractJwtPayloadData(jwtTokenPath) + ":" + cfg.AttestationManagerServerPort
		logging.Info("Connecting to server using address generated from JWT at: ", addr)
	} else {
		addr = cfg.AttestationManagerServerAddress + ":" + cfg.AttestationManagerServerPort
		logging.Info("Connecting to server using user provided at: ", addr)
	}

	// Create a context with JWT token
	ctx := GetAuthContext(context.Background(), jwtTokenPath)
	// Log the metadata for debugging
	md, _ := metadata.FromOutgoingContext(ctx)
	logging.Debug("Metadata being sent: ", md)

	// Wrap the existing context with a timeout
	ctx, cancel := context.WithTimeout(ctx, connTimeout)
	defer cancel()

	// Create the TLS configuration
	tlsConfig, err := GetAuthConfig(ctx, caCertPath, nil)
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to create TLS config: %v", err))
		return "", fmt.Errorf("failed to create TLS config: %w", err)
	}
	logging.Debug("TLS credentials created", tlsConfig)

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		logging.Error(fmt.Sprintf("Did not connect: %v", err))
		return "", fmt.Errorf("did not connect: %w", err)
	}
	defer conn.Close()

	// Dump connection info for debugging
	state := conn.GetState()
	logging.Debug("Connection state: ", state.String())

	// Create a new client
	client := pb.NewAttestationStatusMgrServiceClient(conn)

	// Construct the request message
	req := &pb.UpdateInstanceAttestationStatusByHostGuidRequest{
		HostGuid:                hwUUID,
		AttestationStatus:       status,
		AttestationStatusDetail: attestationStatusDetail,
	}

	resp, err := client.UpdateInstanceAttestationStatusByHostGuid(ctx, req)
	if err != nil {
		logging.Error(fmt.Sprintf("Could not update status: %v", err))
		return "", fmt.Errorf("could not update status: %w", err)
	}

	// Log and return the response message
	logging.Info("Response from server: %s\n", resp)

	return " ", nil
}

func InformToAttestationManagerServer(cfg *constants.Config, status pb.AttestationStatus, hostGUID string, attestationStatusDetail string) (string, error) {
	// Call the gRPC client function
	// time.Sleep(10 * time.Second)
	message, err := UpdateNodeAttestationStatus(cfg, status, hostGUID, attestationStatusDetail)
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to update node attestation status: %v", err))
		return "", err
	}
	logging.Info(fmt.Sprintf("Node attestation status updated successfully: %s", message))
	return message, nil
}
