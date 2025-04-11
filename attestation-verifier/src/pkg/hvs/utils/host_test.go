/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

func TestIsLinuxHost(t *testing.T) {
	type args struct {
		hostInfo *model.HostInfo
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Linux",
			args: args{
				hostInfo: &model.HostInfo{
					OSName: "Rhel",
				},
			},
			want: true,
		},
		{
			name: "VMWare ESXI",
			args: args{
				hostInfo: &model.HostInfo{
					OSName: "VMWare ESXI",
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLinuxHost(tt.args.hostInfo); got != tt.want {
				t.Errorf("IsLinuxHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDefaultSoftwareFlavorGroups(t *testing.T) {
	type args struct {
		components []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Default software flavor groups",
			args: args{
				components: []string{"tagent", "wlagent"},
			},
			want: []string{"platform_software", "workload_software"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetDefaultSoftwareFlavorGroups(tt.args.components); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDefaultSoftwareFlavorGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineHostState(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want hvs.HostState
	}{
		{
			name: "Connection time out",
			args: args{
				err: errors.New("connection timed out"),
			},
			want: hvs.HostStateConnectionTimeout,
		},
		{
			name: "Connection failure",
			args: args{
				err: errors.New("connection failure"),
			},
			want: hvs.HostStateConnectionFailure,
		},
		{
			name: "net/http tls timeout",
			args: args{
				err: errors.New("net/http TLS handshake timeout"),
			},
			want: hvs.HostStateConnectionTimeout,
		},
		{
			name: "net/http error",
			args: args{
				err: errors.New("net/http error"),
			},
			want: hvs.HostStateConnectionFailure,
		},
		{
			name: "401 error",
			args: args{
				err: errors.New("401 error"),
			},
			want: hvs.HostStateUnauthorized,
		},
		{
			name: "Unknown state error",
			args: args{
				err: errors.New("Unknown state error"),
			},
			want: hvs.HostStateUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetermineHostState(tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetermineHostState() = %v, want %v", got, tt.want)
			}
		})
	}
}
