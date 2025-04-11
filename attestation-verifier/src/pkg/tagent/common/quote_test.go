/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

const (
	tpmSecretKey          = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	validMeasureLogFile   = "../test/resources/measure-log.json"
	invalidMeasureLogFile = "../test/resources/measure-log-formatted.json"
	testConfigDir         = "../test/resources/config/"
	testRamfsDir          = "../test/resources/ramfs/"
)

var quoteBytes = []byte("7149d2dde1b44f293515f14f80e554ae874c68bde18891e6")

func TestGetTpmQuote(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	intarr := []int{0, 1, 2}
	strarr := []string{"SHA1", "SHA256"}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		quoteRequest       *taModel.TpmQuoteRequest
		aikCertPath        string
		measureLogFilePath string
		ramfsDir           string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *taModel.TpmQuoteResponse
		wantErr bool
	}{
		{
			name: "Error creating tpm provider",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				quoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
					Nonce:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				aikCertPath: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := handler.GetTpmQuote(tt.args.quoteRequest, tt.args.aikCertPath, tt.args.measureLogFilePath, tt.args.ramfsDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.GetTpmQuote() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestHandlerImpl.GetTpmQuote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateTpmQuoteResponse(t *testing.T) {
	os.MkdirAll(testRamfsDir, os.ModePerm)
	os.MkdirAll(testVarDir, os.ModePerm)
	os.MkdirAll(testConfigDir, os.ModePerm)

	CreateTestFile(testConfigDir, RootCert, "aik.pem")
	CreateTestFile(testVarDir, validMeasureLogFile, "measure-log.json")
	CreateTestFile(testRamfsDir, "../test/resources/manifest_tpm20.xml", "manifest_tpm20.xml")

	type args struct {
		cfg                *config.TrustAgentConfiguration
		tpm                tpmprovider.TpmProvider
		tpmQuoteRequest    *taModel.TpmQuoteRequest
		aikCertPath        string
		measureLogFilePath string
		ramfsDir           string
	}

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("IsPcrBankActive", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider.On("GetTpmQuote", mock.Anything, mock.Anything, mock.Anything).Return(quoteBytes, nil)

	mockedTpmProvider2 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider2.On("IsPcrBankActive", mock.Anything).Return(true, nil)
	mockedTpmProvider2.On("NvIndexExists", mock.Anything).Return(true, errors.New("err"))

	mockedTpmProvider3 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider3.On("IsPcrBankActive", mock.Anything).Return(true, errors.New("err"))
	mockedTpmProvider3.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider3.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider3.On("GetTpmQuote", mock.Anything, mock.Anything, mock.Anything).Return(quoteBytes, nil)

	intarr := []int{0, 1, 2}
	strarr := []string{"SHA1", "SHA256"}
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TpmQuoteRequest does not contain a nonce",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
				tpm: mockedTpmProvider,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
					Nonce:    []byte(""),
				},
				aikCertPath: "",
			},
			wantErr: true,
		},
		{
			name: "Error while creating the tpm quote",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
				tpm: mockedTpmProvider2,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
					Nonce:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				aikCertPath: "",
			},
			wantErr: true,
		},
		{
			name: "CreateTpmQuoteResponse from tpm quote data",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
				tpm: mockedTpmProvider,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
					Nonce:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				aikCertPath: "",
			},
			wantErr: false,
		},
		{
			name: "Use default pcr bank",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
				tpm: mockedTpmProvider,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: nil,
					Nonce:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: false,
		},
		{
			name: "Unable to determine PCR bank",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
				tpm: mockedTpmProvider3,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
					Nonce:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "CreateTpmQuoteResponse from tpm quote data" {
				tt.args.aikCertPath = filepath.Join(testConfigDir, "aik.pem")
				tt.args.measureLogFilePath = filepath.Join(testVarDir, "measure-log.json")
				tt.args.ramfsDir = testRamfsDir
			}

			_, err := CreateTpmQuoteResponse(tt.args.cfg, tt.args.tpm, tt.args.tpmQuoteRequest,
				tt.args.aikCertPath, tt.args.measureLogFilePath, tt.args.ramfsDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTpmQuoteResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	DeleteCommonDir(testConfigDir)
	DeleteCommonDir(testVarDir)
}

func TestgetNonce(t *testing.T) {
	type args struct {
		tpmQuoteRequest *taModel.TpmQuoteRequest
		assetTag        string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Get Nonce when asset tag is empty",
			args: args{
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Nonce: []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				assetTag: "",
			},
			wantErr: false,
		},
		{
			name: "Get Nonce when asset tag data is valid",
			args: args{
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Nonce: []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				assetTag: "SGVsbG8sIHBsYXlncm91bmQ=",
			},
			wantErr: false,
		},
		{
			name: "Unable to get nonce with illegal asset tag data",
			args: args{
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Nonce: []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
				},
				assetTag: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f2015ad",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getNonce(tt.args.tpmQuoteRequest, tt.args.assetTag)
			if (err != nil) != tt.wantErr {
				t.Errorf("getNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_readAikAsBase64(t *testing.T) {
	tests := []struct {
		name        string
		aikCertPath string
		want        string
		wantErr     bool
	}{
		{
			name:    "Invalid aik file location",
			wantErr: true,
		},
		{
			name:    "Valid aik file location",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "Valid aik file location" {
				CreateTestFile(testConfigDir, RootCert, "aik.pem")
				tt.aikCertPath = filepath.Join(testConfigDir, "aik.pem")
			}
			_, err := readAikAsBase64(tt.aikCertPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("readAikAsBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	DeleteCommonDir(testConfigDir)
}

func Test_readEventLog(t *testing.T) {
	CreateTestFile(testVarDir, validMeasureLogFile, "measure-log.json")
	CreateTestFile(testVarDir, invalidMeasureLogFile, "measure-log-invalid.json")
	defer DeleteCommonDir(testVarDir)

	tests := []struct {
		name               string
		want               string
		wantErr            bool
		measureLogFilePath string
	}{
		{
			name:               "Invalid MeasureLogFile location",
			measureLogFilePath: "",
			wantErr:            false,
		},
		{
			name:               "Valid MeasureLogFile location",
			measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
			wantErr:            false,
		},
		{
			name:               "Error in Unmarshal MeasureLog data",
			measureLogFilePath: filepath.Join(testVarDir, "measure-log-invalid.json"),
			wantErr:            true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readEventLog(tt.measureLogFilePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("readEventLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_getQuote(t *testing.T) {
	type args struct {
		tpm             tpmprovider.TpmProvider
		tpmQuoteRequest *taModel.TpmQuoteRequest
		nonce           []byte
	}

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("GetTpmQuote", mock.Anything, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	intarr := []int{0, 1, 2}
	strarr := []string{"SHA1", "SHA256"}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Getquote from quote data",
			args: args{
				tpm: mockedTpmProvider,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:     intarr,
					PcrBanks: strarr,
				},
				nonce: []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getQuote(tt.args.tpm, tt.args.tpmQuoteRequest, tt.args.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("getQuote() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_getTcbMeasurements(t *testing.T) {
	CreateTestFile(testRamfsDir, "../test/resources/manifest_tpm20.xml", "manifest_tpm20.xml")
	defer DeleteCommonDir(testRamfsDir)
	tests := []struct {
		name     string
		want     []string
		wantErr  bool
		ramfsDir string
	}{
		{
			name:    "Invalid RamfsDir location",
			wantErr: true,
		},
		{
			name:     "GetTcbMeasurements from valid tcb data",
			ramfsDir: testRamfsDir,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getTcbMeasurements(tt.ramfsDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("getTcbMeasurements() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_getAssetTags(t *testing.T) {
	type args struct {
		tagSecretKey string
		tpm          tpmprovider.TpmProvider
	}

	mockedTpmProvider1 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider1.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider1.On("NvIndexExists", mock.Anything).Return(true, nil)

	mockedTpmProvider2 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider2.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider2.On("NvIndexExists", mock.Anything).Return(true, errors.New("error"))

	mockedTpmProvider3 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider3.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider3.On("NvIndexExists", mock.Anything).Return(false, nil)

	mockedTpmProvider4 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider4.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, errors.New("error"))
	mockedTpmProvider4.On("NvIndexExists", mock.Anything).Return(true, nil)

	mockedTpmProvider5 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider5.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return([]byte(nil), nil)
	mockedTpmProvider5.On("NvIndexExists", mock.Anything).Return(true, nil)

	mockedTpmProvider6 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider6.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return([]byte("ggg"), nil)
	mockedTpmProvider6.On("NvIndexExists", mock.Anything).Return(true, nil)

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "GetAssetTags from valid data",
			args: args{
				tpm:          mockedTpmProvider1,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: false,
		},
		{
			name: "Error while checking existence of Nv Index",
			args: args{
				tpm:          mockedTpmProvider2,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: true,
		},
		{
			name: "Asset tag nvram is not present",
			args: args{
				tpm:          mockedTpmProvider3,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: false,
		},
		{
			name: "Error while performing tpm nv read operation",
			args: args{
				tpm:          mockedTpmProvider4,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: true,
		},
		{
			name: "Tag data was nil",
			args: args{
				tpm:          mockedTpmProvider5,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: true,
		},
		{
			name: "Invalid tag index length",
			args: args{
				tpm:          mockedTpmProvider6,
				tagSecretKey: tpmSecretKey,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getAssetTags(tt.args.tagSecretKey, tt.args.tpm)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAssetTags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_createTpmQuote(t *testing.T) {
	CreateTestFile(testConfigDir, RootCert, "aik.pem")
	CreateTestFile(testVarDir, validMeasureLogFile, "measure-log.json")
	CreateTestFile(testRamfsDir, "../test/resources/manifest_tpm20.xml", "manifest_tpm20.xml")

	type args struct {
		isTAImaEnabled     bool
		tagSecretKey       string
		tpm                tpmprovider.TpmProvider
		tpmQuoteRequest    *taModel.TpmQuoteRequest
		aikCertPath        string
		measureLogFilePath string
		ramfsDir           string
	}

	mockedTpmProvider1 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider1.On("IsPcrBankActive", mock.Anything).Return(true, nil)
	mockedTpmProvider1.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider1.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider1.On("GetTpmQuote", mock.Anything, mock.Anything, mock.Anything).Return(quoteBytes, nil)

	mockedTpmProvider2 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider2.On("NvIndexExists", mock.Anything).Return(true, errors.New("err"))

	mockedTpmProvider3 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider3.On("IsPcrBankActive", mock.Anything).Return(true, nil)
	mockedTpmProvider3.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider3.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider3.On("GetTpmQuote", mock.Anything, mock.Anything, mock.Anything).Return(quoteBytes, errors.New("err"))

	intarr := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	strarr := []string{"SHA1", "SHA256"}
	constants.ProcFilePath = "../test/mockImaDir/procFilePath_Sha256"
	constants.AsciiRuntimeMeasurementFilePath = "../test/mockImaDir/ascii_runtime_measurements"

	tests := []struct {
		name    string
		args    args
		want    *taModel.TpmQuoteResponse
		wantErr bool
	}{
		{
			name: "CreateTpmQuote from valid tpm data",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider1,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: false,
		},
		{
			name: "Error while retrieving asset tags",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider2,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
		{
			name: "Error while retrieving tpm quote request",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider3,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             nil,
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
		{
			name: "Error while retrieving TCB measurements",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider1,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             nil,
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
		{
			name: "Error while getting ima measurements",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider1,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA="),
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
		{
			name: "Error while reading event log",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider1,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             nil,
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
		{
			name: "Error while reading Aik as Base64",
			args: args{
				isTAImaEnabled: true,
				tagSecretKey:   tpmSecretKey,
				tpm:            mockedTpmProvider1,
				tpmQuoteRequest: &taModel.TpmQuoteRequest{
					Pcrs:              intarr,
					PcrBanks:          strarr,
					Nonce:             nil,
					ImaMeasureEnabled: true,
				},
				aikCertPath:        filepath.Join(testConfigDir, "aik.pem"),
				measureLogFilePath: filepath.Join(testVarDir, "measure-log.json"),
				ramfsDir:           testRamfsDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "Error while getting ima measurements" {
				constants.ProcFilePath = "../test/mockImaDir/procFilePath_Sha256"
				constants.AsciiRuntimeMeasurementFilePath = "../test/mockImaDir/ascii_runtime_measurements"
			} else if tt.name == "Error while reading Aik as Base64" {
				tt.args.aikCertPath = filepath.Join(testConfigDir, "aik.pem")
				DeleteCommonDir(testConfigDir)
			} else if tt.name == "Error while reading event log" {
				CreateTestFile(testVarDir, invalidMeasureLogFile, "measure-log.json")
				tt.args.measureLogFilePath = filepath.Join(testVarDir, "measure-log.json")
			} else if tt.name == "Error while retrieving TCB measurements" {
				tt.args.ramfsDir = testRamfsDir
				DeleteCommonDir(testRamfsDir)
			}

			_, err := createTpmQuote(tt.args.isTAImaEnabled, tt.args.tagSecretKey, tt.args.tpm, tt.args.tpmQuoteRequest, tt.args.aikCertPath, tt.args.measureLogFilePath, tt.args.ramfsDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("createTpmQuote() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	DeleteCommonDir(testVarDir)
	DeleteCommonDir(testConfigDir)
	DeleteCommonDir(testRamfsDir)
}
