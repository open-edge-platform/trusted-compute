/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
)

const createHostUniqueFlavorHelpPrompt = "Following environment variables are required for " +
	constants.CreateHostUniqueFlavorCommand + " setup:"

var createHostUniqueFlavorEnvHelp = map[string]string{
	constants.EnvVSAPIURL:    "VS API URL",
	constants.EnvBearerToken: "JWT token for authenticating with VS",
	constants.EnvCurrentIP:   "IP Address of TA deployed host",
	constants.EnvTAHostId:    "Host ID of TA for NATS Connection",
}

type CreateHostUniqueFlavor struct {
	AppConfig      *config.TrustAgentConfiguration
	ClientFactory  hvsclient.HVSClientFactory
	TrustAgentPort int
	envPrefix      string
	commandName    string
}

func (task *CreateHostUniqueFlavor) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, createHostUniqueFlavorHelpPrompt, "", createHostUniqueFlavorEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *CreateHostUniqueFlavor) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

// Run communicates with HVS to establish the host-unique-flavor from the current compute node.
func (task *CreateHostUniqueFlavor) Run() error {
	log.Trace("tasks/create_host_unique_flavor:Run() Entering")
	defer log.Trace("tasks/create_host_unique_flavor:Run() Leaving")
	var err error
	fmt.Println("Running setup task: create-host-unique-flavor")

	flavorsClient, err := task.ClientFactory.FlavorsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create flavor client")
	}

	var taHostName string
	switch task.AppConfig.Mode {
	case constants.CommunicationModeHttp:

		currentIp, err := util.GetCurrentIP()
		if err != nil {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostUniqueFlavorCommand, constants.EnvCurrentIP)
		}
		taHostName = currentIp.String()

	case constants.CommunicationModeOutbound:
		taHostName = task.AppConfig.Nats.HostID
		if taHostName == "" {
			return errors.Errorf("The %s task requires the %s environment variable", constants.CreateHostUniqueFlavorCommand, constants.EnvTAHostId)
		}
	}

	flavorCreateCriteria := hvs.FlavorCreateRequest{
		ConnectionString: util.GetConnectionString(task.AppConfig.Mode, taHostName, task.TrustAgentPort),
		FlavorParts:      []hvs.FlavorPartName{hvs.FlavorPartHostUnique},
	}

	_, err = flavorsClient.CreateFlavor(&flavorCreateCriteria)
	if err != nil {
		return errors.Wrap(err, "Error while creating host unique flavor")
	}

	return nil
}

func (task *CreateHostUniqueFlavor) Validate() error {
	log.Trace("tasks/create_host_unique_flavor:Validate() Entering")
	defer log.Trace("tasks/create_host_unique_flavor:Validate() Leaving")

	switch task.AppConfig.Mode {
	case constants.CommunicationModeHttp:
		_, err := util.GetCurrentIP()
		if err != nil {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostUniqueFlavorCommand, constants.EnvCurrentIP)
		}
	case constants.CommunicationModeOutbound:
		if task.AppConfig.Nats.HostID == "" {
			return errors.Errorf("The %s task requires the %s environment variable", constants.CreateHostUniqueFlavorCommand, constants.EnvTAHostId)
		}
	}

	// no validation is currently implemented (i.e. as long as Run did not fail)
	log.Debug("tasks/create_host_unique_flavor:Validate() Create host unique flavor was successful.")
	return nil
}
