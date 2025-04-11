/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"net"
	"os"
	"reflect"
	"testing"
)

func TestGetCurrentIP(t *testing.T) {

	tests := []struct {
		name    string
		SetEnv  func()
		want    net.IP
		wantErr bool
	}{
		{
			name: "Valid case",
			SetEnv: func() {
				err := os.Setenv("CURRENT_IP", "127.0.0.1")
				if err != nil {
					log.Println("Failed to set ENV CURRENT_IP")
				}
			},
			want:    net.ParseIP("127.0.0.1"),
			wantErr: false,
		},
		{
			name: "Invalid case with Empty value",
			SetEnv: func() {
				err := os.Setenv("CURRENT_IP", "")
				if err != nil {
					log.Println("Failed to set ENV CURRENT_IP")
				}
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid case with invalid IP value",
			SetEnv: func() {
				err := os.Setenv("CURRENT_IP", "256.12.34.235")
				if err != nil {
					log.Println("Failed to set ENV CURRENT_IP")
				}
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.SetEnv()
			got, err := GetCurrentIP()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCurrentIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCurrentIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetConnectionString(t *testing.T) {
	type args struct {
		connType string
		hostname string
		port     int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Valid case with HTTP mode",
			args: args{
				connType: "http",
				hostname: "locahost",
				port:     9443,
			},
			want: "intel:https://locahost:9443",
		},
		{
			name: "Valid case with outboud mode",
			args: args{
				connType: "outbound",
				hostname: "locahost",
				port:     9443,
			},
			want: "intel:nats://locahost",
		},
		{
			name: "Invalid case",
			args: args{
				connType: "",
				hostname: "locahost",
				port:     9443,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetConnectionString(tt.args.connType, tt.args.hostname, tt.args.port); got != tt.want {
				t.Errorf("GetConnectionString() = %v, want %v", got, tt.want)
			}
		})
	}
}
