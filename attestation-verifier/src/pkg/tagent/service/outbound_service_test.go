/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/nats-io/nats.go"
)

func TestTrustAgentOutboundServiceStart(t *testing.T) {

	testHandler := common.NewRequestHandler(&config.TrustAgentConfiguration{})

	type fields struct {
		natsConnection *nats.EncodedConn
		handler        common.RequestHandler
		natsParameters NatsParameters
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Start trustAgentOutboundService",
			fields: fields{
				natsConnection: &nats.EncodedConn{},
				handler:        testHandler,
				natsParameters: NatsParameters{
					NatsService: config.NatsService{
						HostID: "1000",
					},
					TrustedCaCertsDir: "../test/mockCACertsDir",
				},
			},
			wantErr: false,
		},
		{
			name: "Validate trustAgentOutboundService with mock certs",
			fields: fields{
				natsConnection: &nats.EncodedConn{},
				handler:        testHandler,
				natsParameters: NatsParameters{
					NatsService: config.NatsService{
						HostID: "1000",
					},
					TrustedCaCertsDir: "../test/mockCACertsDir",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subscriber := &trustAgentOutboundService{
				natsConnection: tt.fields.natsConnection,
				handler:        tt.fields.handler,
				natsParameters: tt.fields.natsParameters,
			}
			if err := subscriber.Start(); (err != nil) != tt.wantErr {
				t.Errorf("trustAgentOutboundService.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTrustAgentOutboundServiceStop(t *testing.T) {

	testHandler := common.NewRequestHandler(&config.TrustAgentConfiguration{})

	type fields struct {
		natsConnection *nats.EncodedConn
		handler        common.RequestHandler
		natsParameters NatsParameters
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Stop trustAgentOutboundService",
			fields: fields{
				natsConnection: &nats.EncodedConn{},
				handler:        testHandler,
				natsParameters: NatsParameters{
					NatsService: config.NatsService{
						HostID: "1000",
					},
					TrustedCaCertsDir: "../test/mockCACertsDir",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subscriber := &trustAgentOutboundService{
				natsConnection: tt.fields.natsConnection,
				handler:        tt.fields.handler,
				natsParameters: tt.fields.natsParameters,
			}
			if err := subscriber.Stop(); (err != nil) != tt.wantErr {
				t.Errorf("trustAgentOutboundService.Stop() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestrecoverFunc(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Validate recoverFunc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recoverFunc()
		})
	}
}
