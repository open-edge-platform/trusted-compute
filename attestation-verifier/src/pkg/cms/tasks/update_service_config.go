/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"io"
)

type UpdateServiceConfig struct {
	AppConfig     **config.Configuration
	ServerConfig  commConfig.ServerConfig
	AASApiUrl     string
	DefaultPort   int
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"LOG_LEVEL":                  "Log level",
	"LOG_MAX_LENGTH":             "Max length of log statement",
	"LOG_ENABLE_STDOUT":          "Enable console log",
	"AAS_BASE_URL":               "AAS Base URL",
	"TOKEN_DURATION_MINS":        "Validity of token duration",
	"SERVER_PORT":                "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":        "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT": "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":       "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":        "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":    "Max Length Of Request Header in Bytes",
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_config:Run() Entering")
	defer log.Trace("tasks/update_config:Run() Leaving")

	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt(commConfig.LogMaxLength),
		EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
		Level:        viper.GetString(commConfig.LogLevel),
	}

	(*uc.AppConfig).AASApiUrl = viper.GetString(commConfig.AasBaseUrl)

	(*uc.AppConfig).TokenDurationMins = viper.GetInt(config.TokenDurationMins)
	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 {
		uc.ServerConfig.Port = uc.DefaultPort
	}
	(*uc.AppConfig).Server = uc.ServerConfig
	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	if (*uc.AppConfig).Server.Port < 1024 ||
		(*uc.AppConfig).Server.Port > 65535 {
		return errors.New("Configured port is not valid")
	}
	return nil
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, envHelpPrompt, "", envHelp)
	fmt.Fprintln(w, "")
}

func (uc UpdateServiceConfig) SetName(n, e string) {
}
