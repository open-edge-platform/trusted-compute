/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
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
	CACertValidity     = "cms-ca.cert-validity"
	CACertOrganization = "cms-ca.organization"
	CACertLocality     = "cms-ca.locality"
	CACertProvince     = "cms-ca.province"
	CACertCountry      = "cms-ca.country"

	TlsSanList        = "san-list"
	TokenDurationMins = "token-duration-mins"

	AasJwtCn  = "aas-jwt-cn"
	AasTlsCn  = "aas-tls-cn"
	AasTlsSan = "aas-tls-san"
)

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
type Configuration struct {
	Log               commConfig.LogConfig    `yaml:"log"`
	AASApiUrl         string                  `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CACert            CACertConfig            `yaml:"cms-ca" mapstructure:"cms-ca"`
	TlsCertDigest     string                  `yaml:"tls-cert-digest" mapstructure:"tls-cert-digest"`
	TlsSanList        string                  `yaml:"san-list" mapstructure:"san-list"`
	TokenDurationMins int                     `yaml:"token-duration-mins" mapstructure:"token-duration-mins"`
	Server            commConfig.ServerConfig `yaml:"server"`
	AasJwtCn          string                  `yaml:"aas-jwt-cn" mapstructure:"aas-jwt-cn"`
	AasTlsCn          string                  `yaml:"aas-tls-cn" mapstructure:"aas-tls-cn"`
	AasTlsSan         string                  `yaml:"aas-tls-san" mapstructure:"aas-tls-san"`
}

type CACertConfig struct {
	Validity     int    `yaml:"cert-validity" mapstructure:"cert-validity"`
	Organization string `yaml:"organization" mapstructure:"organization"`
	Locality     string `yaml:"locality" mapstructure:"locality"`
	Province     string `yaml:"province" mapstructure:"province"`
	Country      string `yaml:"country" mapstructure:"country"`
}

// this function sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constants.ConfigDir)
}

func (c *Configuration) Save(filename string) error {
	configFile, err := cos.OpenFileSafe(filename, "", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing config file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(c)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}

func Load() (*Configuration, error) {
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
