/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const updateServiceConfigOptionalEnvHelpPrompt = "Following environment optional are required for " +
	constants.UpdateServiceConfigCommand + " setup:"
const updateServiceConfigRequiredEnvHelpPrompt = "Following environment variables are required for " +
	constants.UpdateServiceConfigCommand + " setup:"

var optionalEnvHelp = map[string]string{
	constants.EnvTAPort:                    "Trust Agent Listener Port",
	constants.EnvTAServerReadTimeout:       "Trustagent Server Read Timeout",
	constants.EnvTAServerReadHeaderTimeout: "Trustagent Read Header Timeout",
	constants.EnvTAServerWriteTimeout:      "Tustagent Write Timeout",
	constants.EnvTAServerIdleTimeout:       "Trustagent Idle Timeout",
	constants.EnvTAServerMaxHeaderBytes:    "Trustagent Max Header Bytes Timeout",
	constants.EnvTALogLevel:                "Logging Level",
	constants.EnvTALogEnableConsoleLog:     "Trustagent Enable standard output",
	constants.EnvLogEntryMaxlength:         "Maximum length of each entry in a log",
	constants.EnvNATServers:                "Comma-separated list of NATs servers",
}

var requiredEnvHelp = map[string]string{
	constants.EnvServiceUser:     "The service username as configured in AAS",
	constants.EnvServicePassword: "The service password as configured in AAS",
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type UpdateServiceConfig struct {
	AppConfig     *config.TrustAgentConfiguration
	ServerConfig  commConfig.ServerConfig
	LoggingConfig commConfig.LogConfig
	AASApiUrl     string
	NatServers    config.NatsService
	envPrefix     string
	commandName   string
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, updateServiceConfigRequiredEnvHelpPrompt, "", requiredEnvHelp)
	fmt.Fprintln(w, "")
	setup.PrintEnvHelp(w, updateServiceConfigOptionalEnvHelpPrompt, "", optionalEnvHelp)
	fmt.Fprintln(w, "")
}

func (uc *UpdateServiceConfig) SetName(n, e string) {
	uc.commandName = n
	uc.envPrefix = setup.PrefixUnderscroll(e)
}

func (uc *UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_service_config:Run() Entering")
	defer log.Trace("tasks/update_service_config:Run() Leaving")
	fmt.Println("Running setup task: update-service-config")

	if _, err := url.ParseRequestURI(uc.AASApiUrl); err != nil && uc.AppConfig.Aas.BaseURL == "" {
		return errors.Errorf("Invalid %s provided", constants.EnvAASBaseURL)
	}
	if !strings.HasSuffix(uc.AASApiUrl, "/") {
		uc.AASApiUrl += "/"
	}
	uc.AppConfig.Aas.BaseURL = uc.AASApiUrl

	// HTTP Server Settings
	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 && uc.AppConfig.Server.Port == 0 {
		log.Warnf("Invalid %s provided. using default value:", constants.EnvTAPort)
		uc.ServerConfig.Port = constants.DefaultPort
	}

	if uc.ServerConfig.MaxHeaderBytes < 1 && uc.AppConfig.Server.MaxHeaderBytes == 0 {
		log.Warnf("Invalid %s provided. using default value:", constants.EnvTAServerMaxHeaderBytes)
		uc.ServerConfig.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	}

	if uc.ServerConfig.ReadTimeout < 1 && uc.AppConfig.Server.ReadTimeout == 0 {
		log.Warnf("Invalid %s provided. using default value:", constants.EnvTAServerReadTimeout)
		uc.ServerConfig.ReadTimeout = constants.DefaultReadTimeout
	}

	if uc.ServerConfig.ReadHeaderTimeout < 1 && uc.AppConfig.Server.ReadHeaderTimeout == 0 {
		log.Warnf("Invalid %s provided. using default value:", constants.EnvTAServerReadHeaderTimeout)
		uc.ServerConfig.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	}

	if uc.ServerConfig.IdleTimeout < 1 && uc.AppConfig.Server.IdleTimeout == 0 {
		log.Warnf("Invalid %s provided. using default value:", constants.EnvTAServerIdleTimeout)
		uc.ServerConfig.IdleTimeout = constants.DefaultIdleTimeout
	}
	uc.AppConfig.Server = uc.ServerConfig

	// NATS Server Settings
	// Ensure NATs server list is only populated if communication mode is outbound
	if uc.AppConfig.Mode == constants.CommunicationModeOutbound {
		if len(uc.NatServers.Servers) == 0 || len(uc.NatServers.Servers) == 1 && strings.TrimSpace(uc.NatServers.Servers[0]) == "" {
			return errors.Errorf("Invalid %s provided", constants.EnvNATServers)
		}
		uc.AppConfig.Nats.Servers = uc.NatServers.Servers

		if len(uc.NatServers.HostID) > 0 {
			uc.AppConfig.Nats.HostID = uc.NatServers.HostID
		}
	}

	// LOG_ENTRY_MAXLENGTH
	if uc.LoggingConfig.MaxLength < constants.DefaultLogEntryMaxlength {
		log.Warnf("Invalid %s defined (should be >= %d) using default value:", constants.EnvLogEntryMaxlength, constants.DefaultLogEntryMaxlength)
		uc.LoggingConfig.MaxLength = constants.DefaultLogEntryMaxlength
	}

	// TRUSTAGENT_LOG_LEVEL
	if _, err := logrus.ParseLevel(uc.LoggingConfig.Level); err != nil ||
		strings.TrimSpace(uc.LoggingConfig.Level) == "" {
		log.Warnf("Invalid %s. using default value", constants.EnvTALogLevel)
		uc.LoggingConfig.Level = constants.DefaultLogLevel
	}
	uc.AppConfig.Logging = uc.LoggingConfig

	return nil
}

func (uc *UpdateServiceConfig) Validate() error {
	log.Trace("tasks/update_service_config:Validate() Entering")
	defer log.Trace("tasks/update_service_config:Validate() Leaving")
	if uc.AppConfig.Aas.BaseURL == "" {
		return errors.New("The Trust-Agent service requires that the configuration contains AAS base url")
	}
	// check if the communication mode is set and required settings are there
	switch uc.AppConfig.Mode {
	case constants.CommunicationModeHttp:
		if uc.AppConfig.Server.Port < 1024 || uc.ServerConfig.Port > 65535 {
			return errors.Errorf("The Trust-Agent service requires that the configuration contains a valid port number: '%d'", (*uc.AppConfig).Server.Port)
		}
	case constants.CommunicationModeOutbound:
		if len(uc.AppConfig.Nats.Servers) == 0 {
			return errors.Errorf("The Trust-Agent service in outbound mode requires a list of %s", constants.EnvNATServers)
		}
		if strings.TrimSpace(uc.AppConfig.Nats.HostID) == "" {
			return errors.Errorf("The Trust-Agent service in outbound mode requires a non-empty %s", constants.EnvTAHostId)
		}
	}

	log.Debug("tasks/update_service_config:Validate() update_service_config task was successful")
	return nil
}
