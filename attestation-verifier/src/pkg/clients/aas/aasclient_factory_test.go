/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	log "github.com/sirupsen/logrus"
)

const (
	testRunBasePath = "../../../test/"
	goodCaDir       = "goodCas"
	badCaDir        = "badCas"
	badCaFile       = "badca.pem"
	goodAasUrl      = "https://localhost:8080/aas/v1/"
	badAasUrl       = "thisisnotagoodurl"
	goodBearerToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"
	badBearerToken  = ""
	badCaData       = "Thisisabadpemfile"
)

var (
	goodCaPath = path.Join(testRunBasePath, goodCaDir)
	badCaPath  = path.Join(testRunBasePath, badCaDir)
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)

}

func shutdown() {
	os.RemoveAll(badCaPath)
	os.RemoveAll(goodCaPath)
}

func setup() {
	// setup ca cert dirs for the tests
	caCertBytes, _, err := crypt.CreateKeyPairAndCertificate(consts.DefaultCertIssuer, "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
	if err != nil {
		log.WithError(err).Errorf("Failed create certificate")
	}

	os.MkdirAll(goodCaPath, os.ModePerm)
	os.MkdirAll(badCaPath, os.ModePerm)
	_ = crypt.SavePemCert(caCertBytes, goodCaPath)
	if err != nil {
		log.WithError(err).Errorf("Failed save certificate")
	}

	err = ioutil.WriteFile(path.Join(badCaPath, badCaFile), []byte(badCaData), os.ModePerm)
	if err != nil {
		log.WithError(err).Errorf("Failed save certificate")
	}
}

func TestDefaultAasClientFactory_GetAasClient(t *testing.T) {
	type fields struct {
		AasUrl      string
		BearerToken string
		CaCertsDir  string
	}
	tests := []struct {
		name    string
		fields  fields
		want    Client
		wantErr bool
	}{
		{
			name: "Successful AAS client",
			fields: fields{
				AasUrl:      goodAasUrl,
				BearerToken: goodBearerToken,
				CaCertsDir:  goodCaPath,
			},
			wantErr: false,
		},
		{
			name: "Invalid AAS URL",
			fields: fields{
				AasUrl:      badAasUrl,
				BearerToken: goodBearerToken,
				CaCertsDir:  goodCaPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid Bearer Token",
			fields: fields{
				AasUrl:      goodAasUrl,
				BearerToken: badBearerToken,
				CaCertsDir:  goodCaPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid CA dir path",
			fields: fields{
				AasUrl:      goodAasUrl,
				BearerToken: goodBearerToken,
				CaCertsDir:  badCaDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aasCp := DefaultAasClientProvider{
				AasUrl:      tt.fields.AasUrl,
				BearerToken: tt.fields.BearerToken,
				CaCertsDir:  tt.fields.CaCertsDir,
			}
			_, err := aasCp.GetAasClient()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAasClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
