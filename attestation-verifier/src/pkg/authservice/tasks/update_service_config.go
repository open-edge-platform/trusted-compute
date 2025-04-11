/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"io"
)

type UpdateServiceConfig struct {
	AppConfig     **config.Configuration
	ServerConfig  commConfig.ServerConfig
	DefaultPort   int
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"LOG_LEVEL":                           "Log level",
	"LOG_MAX_LENGTH":                      "Max length of log statement",
	"LOG_ENABLE_STDOUT":                   "Enable console log",
	"JWT_INCLUDE_KID":                     "Includes JWT Key Id for token validation",
	"JWT_TOKEN_DURATION_MINS":             "Validity of token duration",
	"JWT_CERT_COMMON_NAME":                "Common Name for JWT Certificate",
	"AUTH_DEFENDER_MAX_ATTEMPTS":          "Auth defender maximum attempts",
	"AUTH_DEFENDER_INTERVAL_MINS":         "Auth defender interval in minutes",
	"AUTH_DEFENDER_LOCKOUT_DURATION_MINS": "Auth defender lockout duration in minutes",
	"SERVER_PORT":                         "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":                 "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT":          "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":                "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":                 "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":             "Max Length Of Request Header in Bytes",
	"NATS_OPERATOR_NAME":                  "Set the NATS operator name, default is \"ISecL-operator\"",
	"NATS_OPERATOR_CREDENTIAL_VALIDITY":   "Set the NATS operator credential validity, default is 5 years",
	"NATS_ACCOUNT_NAME":                   "Set the NATS account name, default is \"ISecL-account\"",
	"NATS_ACCOUNT_CREDENTIAL_VALIDITY":    "Set the NATS account credential validity, default is 5 years",
	"NATS_USER_CREDENTIAL_VALIDITY":       "Set the NATS user credential validity, default is 1 year",
}

func (uc UpdateServiceConfig) Run() error {
	defaultLog.Trace("tasks/update_service_config:Run() Entering")
	defer defaultLog.Trace("tasks/update_service_config:Run() Leaving")
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt(commConfig.LogMaxLength),
		EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
		Level:        viper.GetString(commConfig.LogLevel),
	}

	(*uc.AppConfig).JWT = config.JWT{
		IncludeKid:        viper.GetBool(config.JwtIncludeKid),
		TokenDurationMins: viper.GetInt(config.JwtTokenDurationMins),
		CertCommonName:    viper.GetString(config.JwtCertCommonName),
	}

	(*uc.AppConfig).AuthDefender = config.AuthDefender{
		MaxAttempts:         viper.GetInt(config.AuthDefenderMaxAttempts),
		IntervalMins:        viper.GetInt(config.AuthDefenderIntervalMins),
		LockoutDurationMins: viper.GetInt(config.AuthDefenderLockoutDurationMins),
	}

	(*uc.AppConfig).Nats = config.NatsConfig{
		Operator: config.NatsEntityInfo{
			Name:               viper.GetString(config.NatsOperatorName),
			CredentialValidity: viper.GetDuration(config.NatsOperatorCredentialValidity),
		},
		Account: config.NatsEntityInfo{
			Name:               viper.GetString(config.NatsAccountName),
			CredentialValidity: viper.GetDuration(config.NatsAccountCredentialValidity),
		},
		UserCredentialValidity: viper.GetDuration(config.NatsUserCredentialValidity),
	}

	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 {
		uc.ServerConfig.Port = uc.DefaultPort
	}
	(*uc.AppConfig).Server = uc.ServerConfig
	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	defaultLog.Trace("tasks/update_service_config:Validate() Entering")
	defer defaultLog.Trace("tasks/update_service_config:Validate() Leaving")
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
