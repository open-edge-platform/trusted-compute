/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"io"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"gopkg.in/yaml.v3"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	commLogInt "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/setup"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type NatsService struct {
	Servers []string `yaml:"servers" mapstructure:"servers"`
	HostID  string   `yaml:"host-id" mapstructure:"host-id"`
}

type HvsConfig struct {
	Url string `yaml:"url" mapstructure:"url"`
}

type TpmConfig struct {
	TagSecretKey string `yaml:"tag-secret-key" mapstructure:"tag-secret-key"`
}

type AasConfig struct {
	BaseURL string `yaml:"base-url" mapstructure:"base-url"`
}

type CmsConfig struct {
	BaseURL       string `yaml:"base-url" mapstructure:"base-url"`
	TLSCertDigest string `yaml:"tls-cert-sha384" mapstructure:"tls-cert-sha384"`
}

type TlsConfig struct {
	CommonName string `yaml:"common-name" mapstructure:"common-name"`
	SANList    string `yaml:"san-list" mapstructure:"san-list"`
}

type TrustAgentConfiguration struct {
	Mode              string                  `yaml:"ta-service-mode" mapstructure:"ta-service-mode"`
	Logging           commConfig.LogConfig    `yaml:"log" mapstructure:"log"`
	Server            commConfig.ServerConfig `yaml:"server" mapstructure:"server"`
	HVS               HvsConfig               `yaml:"hvs" mapstructure:"hvs"`
	Tpm               TpmConfig               `yaml:"tpm" mapstructure:"tpm"`
	Aas               AasConfig               `yaml:"aas" mapstructure:"aas"`
	Cms               CmsConfig               `yaml:"cms" mapstructure:"cms"`
	Tls               TlsConfig               `yaml:"tls" mapstructure:"tls"`
	Nats              NatsService             `yaml:"nats" mapstructure:"nats"`
	ApiToken          string                  `yaml:"api-token" mapstructure:"api-token"`
	ImaMeasureEnabled bool                    `yaml:"ima-measure-enabled" mapstructure:"ima-measure-enabled"`
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constants.ConfigDir)
}

// LoadConfiguration loads the persisted configuration from disk
func LoadConfiguration() (*TrustAgentConfiguration, error) {
	ret := TrustAgentConfiguration{}
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

// SaveConfiguration method used to save the configuration
func (cfg *TrustAgentConfiguration) SaveConfiguration(filename string) error {
	configFile, err := cos.OpenFileSafe(filename, "", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(cfg)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}

	if err := os.Chmod(filename, 0640); err != nil {
		return errors.Wrap(err, "Failed to apply permissions to config file")
	}
	return nil
}

func (cfg *TrustAgentConfiguration) LogConfiguration(stdOut bool) {
	log.Trace("config/config:LogConfiguration() Entering")
	defer log.Trace("config/config:LogConfiguration() Leaving")

	// creating the log file if not preset
	var ioWriterDefault io.Writer
	var err error = nil
	defaultLogFile, _ := cos.OpenFileSafe(constants.DefaultLogFilePath, "", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	err = os.Chmod(constants.DefaultLogFilePath, 0640)
	if err != nil {
		log.Errorf("config/config:LogConfiguration() error in setting file permission for file : %s", constants.DefaultLogFilePath)
	}

	secLogFile, _ := cos.OpenFileSafe(constants.SecurityLogFilePath, "", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	err = os.Chmod(constants.SecurityLogFilePath, 0640)
	if err != nil {
		log.Errorf("config/config:LogConfiguration() error in setting file permission for file : %s", constants.SecurityLogFilePath)
	}

	ioWriterDefault = defaultLogFile
	if stdOut {
		ioWriterDefault = io.MultiWriter(os.Stdout, defaultLogFile)
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, secLogFile)

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = logrus.InfoLevel.String()
	}

	llp, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		cfg.Logging.Level = logrus.InfoLevel.String()
		llp, _ = logrus.ParseLevel(cfg.Logging.Level)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.Logging.MaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.Logging.MaxLength}, ioWriterSecurity, false)

	secLog.Infof("config/config:LogConfiguration() %s", message.LogInit)
	log.Infof("config/config:LogConfiguration() %s", message.LogInit)
}
