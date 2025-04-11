/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

const downloadCredentialEnvHelpPrompt = "Following environment variables are required for " +
	constants.DownloadCredentialCommand + " setup:"

var downloadCredentialEnvHelp = map[string]string{
	constants.EnvAASBaseURL:  "AAS API URL",
	constants.EnvBearerToken: "JWT token for authenticating with VS",
}

type DownloadCredential struct {
	Mode              string
	AasClientProvider aas.AasClientProvider
	HostId            string
	envPrefix         string
	commandName       string
	NatsCredentials   string
}

func (task *DownloadCredential) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, downloadCredentialEnvHelpPrompt, "", downloadCredentialEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *DownloadCredential) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

//
// Downloads Credential file for message queue server from AAS
//
func (task *DownloadCredential) Run() error {
	log.Trace("tasks/download_credential:Run() Entering")
	defer log.Trace("tasks/download_credential:Run() Leaving")

	var err error
	fmt.Println("Running setup task: download-credential")

	// get the aas client from provider
	aasc, err := task.AasClientProvider.GetAasClient()
	if err != nil {
		return err
	}

	params := types.Parameters{
		TaHostId: &task.HostId,
	}
	ccReq := types.CreateCredentialsReq{
		ComponentType: constants.TAServiceName,
		Parameters:    &params,
	}
	credentialFileBytes, err := aasc.GetCredentials(ccReq)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving credential file from aas")
	}

	err = ioutil.WriteFile(task.NatsCredentials, credentialFileBytes, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error while saving %s", task.NatsCredentials)
	}

	return nil
}

// Validate Assume task is successful if nats credential file already exists
func (task *DownloadCredential) Validate() error {
	log.Trace("tasks/download_credential:Validate() Entering")
	defer log.Trace("tasks/download_credential:Validate() Leaving")

	_, err := os.Stat(task.NatsCredentials)
	if os.IsNotExist(err) {
		return errors.Errorf("%s file does not exist", task.NatsCredentials)
	}

	log.Debug("tasks/download_credential:Validate() download-credentials setup task was successful.")
	return nil
}
