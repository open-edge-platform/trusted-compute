/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"testing"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func TestNewTrustAgentService(t *testing.T) {
	type args struct {
		parameters *ServiceParameters
	}
	tests := []struct {
		name    string
		args    args
		want    TrustAgentService
		wantErr bool
	}{
		{
			name: "Create new NewTrustAgentService",
			args: args{
				parameters: &ServiceParameters{
					Mode: "outbound",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "test ID",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Validate when host id is nil",
			args: args{
				parameters: &ServiceParameters{
					Mode: "outbound",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Validate when mode is outbound",
			args: args{
				parameters: &ServiceParameters{
					Mode: "outbound",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "test ID",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Validate when mode is unknown",
			args: args{
				parameters: &ServiceParameters{
					Mode: "unknownmode",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "test ID",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Validate when mode is empty with empty port",
			args: args{
				parameters: &ServiceParameters{
					Mode: "",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "test ID",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Validate when mode is empty",
			args: args{
				parameters: &ServiceParameters{
					Mode: "",
					Nats: NatsParameters{
						NatsService: config.NatsService{
							HostID: "test ID",
						},
					},
					Web: WebParameters{
						ServerConfig: commConfig.ServerConfig{
							Port: 8080,
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTrustAgentService(tt.args.parameters)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTrustAgentService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
