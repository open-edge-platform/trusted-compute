/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Constants for viper variable names. Will be used to set
// default values as well as to get each value
const (
	AasServiceUsername = "aas.service-username"
	AasServicePassword = "aas.service-password"

	JwtIncludeKid        = "jwt.include-kid"
	JwtCertCommonName    = "jwt.cert-common-name"
	JwtTokenDurationMins = "jwt.token-duration-mins"

	AuthDefenderMaxAttempts         = "auth-defender.max-attempts"
	AuthDefenderIntervalMins        = "auth-defender.interval-mins"
	AuthDefenderLockoutDurationMins = "auth-defender.lockout-duration-mins"

	CreateCredentials = "create-credentials"

	NatsOperatorName               = "nats.operator.name"
	NatsOperatorCredentialValidity = "nats.operator.credential-validity"
	NatsAccountName                = "nats.account.name"
	NatsAccountCredentialValidity  = "nats.account.credential-validity"
	NatsUserCredentialValidity     = "nats.user-credential-validity"
)

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	CMSBaseURL       string                   `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string                   `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`
	AAS              AASConfig                `yaml:"aas"`
	DB               commConfig.DBConfig      `yaml:"db"`
	Log              commConfig.LogConfig     `yaml:"log"`
	AuthDefender     AuthDefender             `yaml:"auth-defender"`
	JWT              JWT                      `yaml:"jwt"`
	TLS              commConfig.TLSCertConfig `yaml:"tls"`
	Server           commConfig.ServerConfig  `yaml:"server"`
	Nats             NatsConfig               `yaml:"nats"`
}

type AASConfig struct {
	Username string `yaml:"service-username" mapstructure:"service-username"`
	Password string `yaml:"service-password" mapstructure:"service-password"`
}

type JWT struct {
	IncludeKid        bool   `yaml:"include-kid" mapstructure:"include-kid"`
	TokenDurationMins int    `yaml:"token-duration-mins" mapstructure:"token-duration-mins"`
	CertCommonName    string `yaml:"cert-common-name" mapstructure:"cert-common-name"`
}

type AuthDefender struct {
	MaxAttempts         int `yaml:"max-attempts" mapstructure:"max-attempts"`
	IntervalMins        int `yaml:"interval-mins" mapstructure:"interval-mins"`
	LockoutDurationMins int `yaml:"lockout-duration-mins" mapstructure:"lockout-duration-mins"`
}

type NatsConfig struct {
	Operator               NatsEntityInfo `yaml:"operator" mapstructure:"operator"`
	Account                NatsEntityInfo `yaml:"account" mapstructure:"account"`
	UserCredentialValidity time.Duration  `yaml:"user-credential-validity" mapstructure:"user-credential-validity"`
}

type NatsEntityInfo struct {
	Name               string        `yaml:"name" mapstructure:"name"`
	CredentialValidity time.Duration `yaml:"credential-validity" mapstructure:"credential-validity"`
}

// this function sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constants.ConfigDir)
}

func (conf *Configuration) Save(filename string) error {
	configFile, err := cos.OpenFileSafe(filename, "", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Errorf("Error closing config file")
		}
	}()

	err = yaml.NewEncoder(configFile).Encode(conf)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}

func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}
