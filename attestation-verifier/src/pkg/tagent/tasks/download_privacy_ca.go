/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
)

const downloadPrivacyCAEnvHelpPrompt = "Following environment variables are required for " +
	constants.DownloadPrivacyCACommand + " setup:"

var downloadPrivacyCAEnvHelp = map[string]string{
	constants.EnvVSAPIURL:    "VS API URL",
	constants.EnvBearerToken: "JWT token for authenticating with VS",
	constants.EnvCurrentIP:   "IP Address of TA deployed host",
}

type DownloadPrivacyCA struct {
	ClientFactory hvsclient.HVSClientFactory
	envPrefix     string
	commandName   string
	PrivacyCA     string
}

func (task *DownloadPrivacyCA) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, downloadPrivacyCAEnvHelpPrompt, "", downloadPrivacyCAEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *DownloadPrivacyCA) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

// Download's the privacy CA from HVS.
func (task *DownloadPrivacyCA) Run() error {
	log.Trace("tasks/download_privacy_ca:Run() Entering")
	defer log.Trace("tasks/download_privacy_ca:Run() Leaving")
	fmt.Println("Running setup task: download-privacy-ca")

	var err error

	privacyCAClient, err := task.ClientFactory.PrivacyCAClient()
	if err != nil {
		return errors.Wrap(err, "Could not create privacy-ca client")
	}

	ca, err := privacyCAClient.DownloadPrivacyCa()
	if err != nil {
		return errors.Wrap(err, "Error while downloading privacyCA file")
	}

	err = ioutil.WriteFile(task.PrivacyCA, ca, 0644)
	if err != nil {
		return errors.Wrapf(err, "Error while writing privacy ca file '%s'", task.PrivacyCA)
	}

	return nil
}

func (task *DownloadPrivacyCA) Validate() error {
	log.Trace("tasks/download_privacy_ca:Validate() Entering")
	defer log.Trace("tasks/download_privacy_ca:Validate() Leaving")
	var err error

	_, err = util.GetPrivacyCA(task.PrivacyCA)
	if err != nil {
		return err
	}

	log.Debug("tasks/download_privacy_ca:Validate() Download PrivacyCA was successful")
	return nil
}
