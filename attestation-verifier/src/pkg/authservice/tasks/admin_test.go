/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres/mock"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestCreateAdmin(t *testing.T) {
	m := &mock.MockDatabase{}
	c := config.Configuration{}
	var user *types.User
	var role *types.Role
	var permission *types.Permission
	m.MockUserStore.CreateFunc = func(u types.User) (*types.User, error) {
		user = &u
		return user, nil
	}
	m.MockUserStore.RetrieveFunc = func(u types.User) (*types.User, error) {
		if user == nil {
			return nil, errors.New("Record not found")
		}
		return user, nil
	}
	m.MockRoleStore.CreateFunc = func(r types.Role) (*types.Role, error) {
		role = &r
		return role, nil
	}
	m.MockRoleStore.RetrieveFunc = func(r *types.RoleSearch) (*types.Role, error) {
		if role == nil {
			return nil, errors.New("Record not found")
		}
		return role, nil
	}
	m.MockPermissionStore.CreateFunc = func(p types.Permission) (*types.Permission, error) {
		permission = &p
		return permission, nil
	}
	m.MockPermissionStore.RetrieveFunc = func(r *types.PermissionSearch) (*types.Permission, error) {
		if permission == nil {
			return nil, errors.New("Record not found")
		}
		return permission, nil
	}

	serviceConfig := config.AASConfig{
		Username: "username",
		Password: "password",
	}

	task := Admin{
		ServiceConfigPtr: &c.AAS,
		AASConfig:        serviceConfig,
		DatabaseFactory: func() (domain.AASDatabase, error) {
			return m, nil
		},
		ConsoleWriter: os.Stdout,
	}
	err := task.Run()
	assert.NoError(t, err)
}

func TestAdmin_Validate(t *testing.T) {
	type fields struct {
		AASConfig        config.AASConfig
		ServiceConfigPtr *config.AASConfig
		DatabaseFactory  func() (domain.AASDatabase, error)
		ConsoleWriter    io.Writer
		envPrefix        string
		commandName      string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "validate username with empty string",
			fields: fields{
				ServiceConfigPtr: &config.AASConfig{
					Username: "",
				},
			},
			wantErr: true,
		},
		{
			name: "validate password with empty string",
			fields: fields{
				ServiceConfigPtr: &config.AASConfig{
					Username: "test",
					Password: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate username and password with valid string",
			fields: fields{
				ServiceConfigPtr: &config.AASConfig{
					Username: "test",
					Password: "test",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Admin{
				AASConfig:        tt.fields.AASConfig,
				ServiceConfigPtr: tt.fields.ServiceConfigPtr,
				DatabaseFactory:  tt.fields.DatabaseFactory,
				ConsoleWriter:    tt.fields.ConsoleWriter,
				envPrefix:        tt.fields.envPrefix,
				commandName:      tt.fields.commandName,
			}
			if err := a.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Admin.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdmin_SetName(t *testing.T) {
	type fields struct {
		AASConfig        config.AASConfig
		ServiceConfigPtr *config.AASConfig
		DatabaseFactory  func() (domain.AASDatabase, error)
		ConsoleWriter    io.Writer
		envPrefix        string
		commandName      string
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Validate SetName with valid string",
			args: args{
				n: "test",
				e: "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Admin{
				AASConfig:        tt.fields.AASConfig,
				ServiceConfigPtr: tt.fields.ServiceConfigPtr,
				DatabaseFactory:  tt.fields.DatabaseFactory,
				ConsoleWriter:    tt.fields.ConsoleWriter,
				envPrefix:        tt.fields.envPrefix,
				commandName:      tt.fields.commandName,
			}
			a.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestAdmin_PrintHelp(t *testing.T) {
	type fields struct {
		AASConfig        config.AASConfig
		ServiceConfigPtr *config.AASConfig
		DatabaseFactory  func() (domain.AASDatabase, error)
		ConsoleWriter    io.Writer
		envPrefix        string
		commandName      string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "valid case",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Admin{
				AASConfig:        tt.fields.AASConfig,
				ServiceConfigPtr: tt.fields.ServiceConfigPtr,
				DatabaseFactory:  tt.fields.DatabaseFactory,
				ConsoleWriter:    tt.fields.ConsoleWriter,
				envPrefix:        tt.fields.envPrefix,
				commandName:      tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			a.PrintHelp(w)
		})
	}
}
