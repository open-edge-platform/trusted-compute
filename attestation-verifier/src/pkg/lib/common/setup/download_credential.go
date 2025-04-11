/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
)

type DownloadCredential struct {
	AasBaseUrL          string
	BearerToken         string
	CreateCredentialReq types.CreateCredentialsReq
	CredentialFilePath  string
	CaCertDirPath       string

	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

const downloadCredentialEnvHelpPrompt = "Following environment variables are used in "

var downloadCredentialEnvCommonHelp = map[string]string{
	"AAS_BASE_URL": "AAS base URL in the format https://{{aas}}:{{aas_port}}/aas/v1/",
	"BEARER_TOKEN": "Bearer token for accessing AAS api",
}

func (dc *DownloadCredential) Run() error {
	if dc.AasBaseUrL == "" {
		return errors.New("AAS_API_URL is not set")
	}
	if dc.BearerToken == "" {
		return errors.New("BEARER_TOKEN is not set")
	}

	printToWriter(dc.ConsoleWriter, dc.commandName, "Start download-credential task")
	caCerts, err := crypt.GetCertsFromDir(dc.CaCertDirPath)
	if err != nil {
		log.WithError(err).Errorf("Error while getting certs from %s", dc.CaCertDirPath)
		return err
	}

	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		log.WithError(err).Errorf("Error while creating http client")
		return err
	}
	aasClient := aas.Client{
		BaseURL:    dc.AasBaseUrL,
		JWTToken:   []byte(dc.BearerToken),
		HTTPClient: client,
	}

	credentialFileBytes, err := aasClient.GetCredentials(dc.CreateCredentialReq)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving credential from aas")
	}

	err = ioutil.WriteFile(dc.CredentialFilePath, credentialFileBytes, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error in saving credential file %s", dc.CredentialFilePath)
	}

	printToWriter(dc.ConsoleWriter, dc.commandName, "credential file saved to "+dc.CredentialFilePath)
	return nil
}

func (dc *DownloadCredential) Validate() error {
	_, err := os.Stat(dc.CredentialFilePath)
	if os.IsNotExist(err) {
		return errors.Errorf("%s does not exists", dc.CredentialFilePath)
	}
	printToWriter(dc.ConsoleWriter, dc.commandName, "download-credential setup validated")
	return nil
}

func (dc *DownloadCredential) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, downloadCredentialEnvHelpPrompt+dc.commandName, "", downloadCredentialEnvCommonHelp)

	fmt.Fprintln(w, "")
}

func (dc *DownloadCredential) SetName(n, e string) {
	dc.commandName = n
	dc.envPrefix = PrefixUnderscroll(e)
}
