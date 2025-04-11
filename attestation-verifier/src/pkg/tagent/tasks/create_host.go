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
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
)

const createHostRequiredEnvHelpPrompt = "Following environment variables are required for " +
	constants.CreateHostCommand + " setup:"

var createHostRequiredEnvHelp = map[string]string{
	constants.EnvVSAPIURL:    "VS API URL",
	constants.EnvBearerToken: "JWT token for authenticating with VS",
	constants.EnvCurrentIP:   "IP Address of TA deployed host for http service mode",
	constants.EnvTAHostId:    "Host ID of TA for NATS Connection nats service mode",
}

type CreateHost struct {
	AppConfig      *config.TrustAgentConfiguration
	ClientFactory  hvsclient.HVSClientFactory
	TrustAgentPort int
	envPrefix      string
	commandName    string
}

func (task *CreateHost) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, createHostRequiredEnvHelpPrompt, "", createHostRequiredEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *CreateHost) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

//
// Registers (or updates) HVS with information about the current compute
// node (providing the connection string, hostname (ip addr) and tls policy).
//
// If the host already exists, create-host will return an error.
//
func (task *CreateHost) Run() error {
	log.Trace("tasks/create_host:Run() Entering")
	defer log.Trace("tasks/create_host:Run() Leaving")

	var err error
	fmt.Println("Running setup task: " + constants.CreateHostCommand)

	hostsClient, err := task.ClientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	var taHostName string
	switch task.AppConfig.Mode {
	case constants.CommunicationModeHttp:
		currentIp, err := util.GetCurrentIP()
		if err != nil {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostCommand, constants.EnvCurrentIP)
		}
		taHostName = currentIp.String()

		// validate the TA port
		if err := validation.ValidatePort(fmt.Sprintf("%d", task.TrustAgentPort)); err != nil {
			return errors.Wrap(err, "Invalid "+constants.EnvTAPort)
		}
	case constants.CommunicationModeOutbound:
		taHostName = task.AppConfig.Nats.HostID
		if taHostName == "" {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostCommand, constants.EnvTAHostId)
		}
	}

	hostCollection, err := hostsClient.SearchHosts(&hvs.HostFilterCriteria{NameEqualTo: taHostName})
	if err != nil {
		return errors.Wrap(err, "Error while retrieving host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		// no host present, create a new one

		hostCreateReq := hvs.HostCreateRequest{
			HostName:         taHostName,
			ConnectionString: util.GetConnectionString(task.AppConfig.Mode, taHostName, task.TrustAgentPort),
		}

		host, err := hostsClient.CreateHost(&hostCreateReq)
		if err != nil {
			return err
		}

		log.Debugf("tasks/create_host:Run() Successfully created host, host id %s", host.Id)
	} else {
		return errors.Errorf("Host with IP address %s already exists", taHostName)
	}

	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task *CreateHost) Validate() error {
	log.Trace("tasks/create_host:Validate() Entering")
	defer log.Trace("tasks/create_host:Validate() Leaving")

	var err error

	hostsClient, err := task.ClientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	var taHostName string
	switch task.AppConfig.Mode {
	case constants.CommunicationModeHttp:
		currentIp, err := util.GetCurrentIP()
		if err != nil {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostCommand, constants.EnvCurrentIP)
		}
		taHostName = currentIp.String()

		// validate the TA port
		if err := validation.ValidatePort(fmt.Sprintf("%d", task.TrustAgentPort)); err != nil {
			return errors.Wrap(err, "Invalid "+constants.EnvTAPort)
		}

	case constants.CommunicationModeOutbound:
		taHostName = task.AppConfig.Nats.HostID
		if taHostName == "" {
			return errors.Wrapf(err, "The %s task requires the %s environment variable", constants.CreateHostCommand, constants.EnvTAHostId)
		}
	}

	hostCollection, err := hostsClient.SearchHosts(&hvs.HostFilterCriteria{NameEqualTo: taHostName})
	if err != nil {
		return errors.Wrap(err, "Error searching for host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		return errors.Errorf("Host %s was not created", taHostName)
	}

	log.Debug("tasks/create_host:Validate() Create host setup task was successful.")
	return nil
}
