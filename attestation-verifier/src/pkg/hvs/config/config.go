/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hrrs"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	HvsServiceUsername = "hvs.service-username"
	HvsServicePassword = "hvs.service-password"

	SamlCertFile        = "saml.common.cert-file"
	SamlKeyFile         = "saml.common.key-file"
	SamlCommonName      = "saml.common.common-name"
	SamlIssuer          = "saml.issuer"
	SamlValiditySeconds = "saml.validity-seconds"

	FlavorSigningCertFile   = "flavor-signing.cert-file"
	FlavorSigningKeyFile    = "flavor-signing.key-file"
	FlavorSigningCommonName = "flavor-signing.common-name"

	PrivacyCaCertFile      = "privacy-ca.cert-file"
	PrivacyCaKeyFile       = "privacy-ca.key-file"
	PrivacyCaCommonName    = "privacy-ca.common-name"
	PrivacyCaIssuer        = "privacy-ca.issuer"
	PrivacyCaValidityYears = "privacy-ca.validity-years"

	EndorsementCaCertFile      = "endorsement-ca.cert-file"
	EndorsementCaKeyFile       = "endorsement-ca.key-file"
	EndorsementCaCommonName    = "endorsement-ca.common-name"
	EndorsementCaIssuer        = "endorsement-ca.issuer"
	EndorsementCaValidityYears = "endorsement-ca.validity-years"

	TagCaCertFile      = "tag-ca.cert-file"
	TagCaKeyFile       = "tag-ca.key-file"
	TagCaCommonName    = "tag-ca.common-name"
	TagCaIssuer        = "tag-ca.issuer"
	TagCaValidityYears = "tag-ca.validity-years"

	AuditLogMaxRowCount = "audit-log.max-row-count"
	AuditLogNumRotated  = "audit-log.number-rotated"
	AuditLogBufferSize  = "audit-log.buffer-size"

	AikCertValidity   = "aik-certificate-validity-years"
	DataEncryptionKey = "data-encryption-key"
	NatsServers       = "nats.servers"

	RequireEKCertForHostProvision  = "require-ek-cert-for-host-provision"
	VerifyQuoteForHostRegistration = "verify-quote-for-host-registration"
)

type Configuration struct {
	AASApiUrl        string `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CMSBaseURL       string `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`

	HVS               commConfig.ServiceConfig `yaml:"hvs"`
	AuditLog          AuditLogConfig           `yaml:"audit-log" mapstructure:"audit-log"`
	IMAMeasureEnabled bool                     `yaml:"ima-measure-enabled" mapstructure:"ima-measure-enabled"`

	TLS           commConfig.TLSCertConfig     `yaml:"tls"`
	SAML          SAMLConfig                   `yaml:"saml"`
	FlavorSigning commConfig.SigningCertConfig `yaml:"flavor-signing" mapstructure:"flavor-signing"`

	PrivacyCA     commConfig.SelfSignedCertConfig `yaml:"privacy-ca" mapstructure:"privacy-ca"`
	EndorsementCA commConfig.SelfSignedCertConfig `yaml:"endorsement-ca" mapstructure:"endorsement-ca"`
	TagCA         commConfig.SelfSignedCertConfig `yaml:"tag-ca" mapstructure:"tag-ca"`

	Dek             string `yaml:"data-encryption-key" mapstructure:"data-encryption-key"`
	AikCertValidity int    `yaml:"aik-certificate-validity-years" mapstructure:"aik-certificate-validity-years"`

	RequireEKCertForHostProvision  bool `yaml:"require-ek-cert-for-host-provision" mapstructure:"require-ek-cert-for-host-provision"`
	VerifyQuoteForHostRegistration bool `yaml:"verify-quote-for-host-registration" mapstructure:"verify-quote-for-host-registration"`

	Server                   commConfig.ServerConfig `yaml:"server"`
	Log                      commConfig.LogConfig    `yaml:"log"`
	DB                       commConfig.DBConfig     `yaml:"db"`
	HRRS                     hrrs.HRRSConfig         `yaml:"hrrs"`
	FVS                      FVSConfig               `yaml:"fvs"`
	VCSS                     VCSSConfig              `yaml:"vcss"`
	NATS                     NatsConfig              `yaml:"nats"`
	EnableEkCertRevokeChecks bool                    `yaml:"enable-ekcert-revoke-check" mapstructure:"enable-ekcert-revoke-check"`
}

type FVSConfig struct {
	NumberOfVerifiers               int  `yaml:"number-of-verifiers" mapstructure:"number-of-verifiers"`
	NumberOfDataFetchers            int  `yaml:"number-of-data-fetchers" mapstructure:"number-of-data-fetchers"`
	SkipFlavorSignatureVerification bool `yaml:"skip-flavor-signature-verification" mapstructure:"skip-flavor-signature-verification"`
	HostTrustCacheThreshold         int  `yaml:"host-trust-cache-threshold" mapstructure:"host-trust-cache-threshold"`
}

type SAMLConfig struct {
	CommonConfig    commConfig.SigningCertConfig `yaml:"common" mapstructure:"common"`
	Issuer          string                       `yaml:"issuer" mapstructure:"issuer"`
	ValiditySeconds int                          `yaml:"validity-seconds" mapstructure:"validity-seconds"`
}

type AuditLogConfig struct {
	MaxRowCount int `yaml:"max-row-count" mapstructure:"max-row-count"`
	NumRotated  int `yaml:"number-rotated" mapstructure:"number-rotated"`
	BufferSize  int `yaml:"buffer-size" mapstructure:"buffer-size"`
}

type VCSSConfig struct {
	// RefreshPeriod determines how frequently the VCSS checks the vCenter cluster for updated hosts
	RefreshPeriod time.Duration `yaml:"refresh-period" mapstructure:"refresh-period"`
}

type NatsConfig struct {
	Servers []string `yaml:"servers" mapstructure:"servers"`
}

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constants.ConfigDir)
}

// config is application specific
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
