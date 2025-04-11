/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"encoding/xml"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetConfiguredManifestPrintHelp(t *testing.T) {
	type fields struct {
		ClientFactory      hvsclient.HVSClientFactory
		savedManifestFiles []string
		envPrefix          string
		commandName        string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print Help for GetConfiguredManifest",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &GetConfiguredManifest{
				ClientFactory:      tt.fields.ClientFactory,
				savedManifestFiles: tt.fields.savedManifestFiles,
				envPrefix:          tt.fields.envPrefix,
				commandName:        tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestGetConfiguredManifestSetName(t *testing.T) {
	type fields struct {
		ClientFactory      hvsclient.HVSClientFactory
		savedManifestFiles []string
		envPrefix          string
		commandName        string
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
			name:   "Set name for GetConfiguredManifest",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &GetConfiguredManifest{
				ClientFactory:      tt.fields.ClientFactory,
				savedManifestFiles: tt.fields.savedManifestFiles,
				envPrefix:          tt.fields.envPrefix,
				commandName:        tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

var invalidLabel = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAwMIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAw"

var invalidUuid = `MIIEBjCCAm6gAwIBAgIRAPZHm6fhowZ8XFgm0iJDPGwwDQYJKoZIhvcNAQEMBQAw
FjEUMBIGA1UEChMLaHZzLXBjYS1haWswHhcNMjIwNDI4MDcyNTI2WhcNMjMwNDI4
MDcyNTI2WjAWMRQwEgYDVQQKEwtodnMtcGNhLWFpazCCAaIwDQYJKoZIhvcNAQEB
BQADggGPADCCAYoCggGBAMhlAE9pCArWorRoXYzDHnLuNYlb+BKfZr3wbU07zSlh
/nadgmkA33/NAHc6IhehM0VlCaYEHzt3cchuEHh2d5wcd7yuq4dFzrmvGSQdMvml
Zu4YijIL6VF7YeyenPf40ozlnSDQ7N5rXHVJVU1k/3PwPN81gDAQ1qgQ/TGpwQhf
3Nw/gGSX8Eu6190aUTJb6SPvRZjqJ+8liFdffVGQJTPYEsfaIOb6wvQ0IhX6cu+O
Wzd3VkLi6X2e3ZOT08CRIPePffQk1jfN3xBAWXrczen4Zahix5eZiFhQ6H+HVGGQ
g7Y8ipfgi0ijNhJlaMrMYBGKzttZ/Imts/tjsdQu7cOU9Ek1A/DX4fsDpAT/3A/n
+Ru25LPuF5ltRnXITWYo2uprVTWfIRZpGOUbrbtFh3dY3lbEbPsajYZoCxoEo73M
T+tEvSy6YEQVF5NdW/fHaJXpVKUCgdXFGbe0o2DBNcx4gyXMHemDkWVapbuOvvir
tZe0AsKaZX3Cv9YTy+9yJwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCAqQwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUdn+oUiGWuCDWaFMtPclWKPgBfe0wCwYDVR0R
BAQwAoIAMA0GCSqGSIb3DQEBDAUAA4IBgQBoir+4j0Mo48oV31gtHGH2NgwIqmqO
BJla3lO8sNjwKSDCIHXWYoJwISnVnXBLvLc2YScsDnW2p/vtxuI3/2/+kh6BEfQE
z8XjlPKJa99AzFcnUffEl6gqiKX0svtSRtiZhfeSXHYWGp/xcrNJBMM16v3hEhsR
JM3UGadFkQhmLU/qCP9YlEpEpeXcdgBfP6zyI7HzHZV1iuwxmpA8QpVQI+KaRgUQ
i8OxVcyaSAJuuq6s1d3uHjf+KvTxjdECsdKIW8zBKBNNFIO4qdLW3uRwW95uUb6j
On92z1G4Y/joyjJxD+olwQv/ePYs/utYI5s5rZJ6KDktsFi1VDey7OT8ZKU0Z8fU
mx2501ZuYBaLrml+IPcheqqKl4dC4lR8ONXK8+22oCv08WoGg8GULXwoBumK+Fl+
X3A+1//gjsTyOGa+ClOkeSWX+G6NgsHq9p7vKdRVbgLRDCKWN5tzZC2t/ZifyiOJ
cj0+sn36+RwZefQLGAdrC7r4REpqhU7ZeRQ`

const (
	testManifestFilePath = "../test/resources/manifest_80ecce40-04b8-e811-906e-00163566263e.xml"
)

func TestGetConfiguredManifestRun(t *testing.T) {

	invalidUuidFormat := "80ecce40-04b8-e811-906e-00163566263e"
	validUuid := uuid.MustParse("f452b331-87f7-4274-a3d2-e31a471d159e")

	manifest := hvsclient.Manifest{
		UUID:  "80ecce40-04b8-e811-906e-00163566263e",
		Label: "test",
	}

	manifestBytes, err := xml.Marshal(manifest)
	if err != nil {
		assert.NoError(t, err)
	}

	mockedManifestsClient := new(hvsclient.MockedManifestsClient)
	os.Setenv(constants.FlavorUUIDs, "80ecce40-04b8-e811-906e-00163566263e")
	mockedManifestsClient.On("GetManifestXmlById", mock.Anything).Return(manifestBytes, nil)
	mockedManifestsClient.On("GetManifestXmlByLabel", mock.Anything).Return(manifestBytes, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedManifestsClient: mockedManifestsClient}

	file, err := os.Create(testManifestFilePath)
	if err != nil {
		assert.NoError(t, err)
	}
	defer file.Close()

	defer func() {
		err = os.Remove(testManifestFilePath)
		assert.NoError(t, err)
	}()

	type fields struct {
		ClientFactory      hvsclient.HVSClientFactory
		savedManifestFiles []string
		envPrefix          string
		commandName        string
		VarDir             string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Test 1 Flavor UUID exceeds maximum length limit",
			fields: fields{
				ClientFactory: mockedVSClientFactory,
				VarDir:        "",
			},
			wantErr: true,
		},
		{
			name: "Test 2 Flavor UUID invalid format",
			fields: fields{
				ClientFactory: mockedVSClientFactory,
				VarDir:        "",
			},
			wantErr: true,
		},
		{
			name: "Test 3 Flavor UUID valid",
			fields: fields{
				ClientFactory: mockedVSClientFactory,
				VarDir:        "",
			},
			wantErr: false,
		},
		{
			name: "Test 4 FlavorLabels exceeds maximum length limit",
			fields: fields{
				ClientFactory: mockedVSClientFactory,
				VarDir:        "",
			},
			wantErr: true,
		},
		{
			name: "Test 5 FlavorLabels valid",
			fields: fields{
				ClientFactory:      mockedVSClientFactory,
				savedManifestFiles: []string{testManifestFilePath},
				VarDir:             "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &GetConfiguredManifest{
				ClientFactory:      tt.fields.ClientFactory,
				savedManifestFiles: tt.fields.savedManifestFiles,
				envPrefix:          tt.fields.envPrefix,
				commandName:        tt.fields.commandName,
				VarDir:             tt.fields.VarDir,
			}

			if tt.name == "Test 1 Flavor UUID exceeds maximum length limit" {
				os.Setenv(constants.FlavorUUIDs, invalidUuid)
			} else if tt.name == "Test 2 Flavor UUID invalid format" {
				os.Setenv(constants.FlavorUUIDs, invalidUuidFormat)
			} else if tt.name == "Test 3 Flavor UUID valid" {
				os.Setenv(constants.FlavorUUIDs, validUuid.String())
			} else if tt.name == "Test 4 FlavorLabels exceeds maximum length limit" {
				os.Setenv(constants.FlavorLabels, invalidLabel)
				os.Setenv(constants.FlavorUUIDs, validUuid.String())
			} else if tt.name == "Test 5 FlavorLabels valid" {
				os.Setenv(constants.FlavorLabels, "PLATFORM")
				os.Setenv(constants.FlavorUUIDs, validUuid.String())
			}

			if err := task.Run(); (err != nil) != tt.wantErr {
				t.Errorf("GetConfiguredManifest.Run() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.name == "Test 5 FlavorLabels valid" {
				if err := task.Validate(); (err != nil) != tt.wantErr {
					t.Errorf("GetConfiguredManifest.Run() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
