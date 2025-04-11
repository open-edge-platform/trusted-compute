/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hrrs"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault(commConfig.TlsCertFile, constants.DefaultTLSCertFile)
	viper.SetDefault(commConfig.TlsKeyFile, constants.DefaultTLSKeyFile)
	viper.SetDefault(commConfig.TlsCommonName, constants.DefaultHvsTlsCn)
	viper.SetDefault(commConfig.TlsSanList, constants.DefaultHvsTlsSan)

	// set default values for all other certs
	viper.SetDefault(config.SamlCertFile, constants.SAMLCertFile)
	viper.SetDefault(config.SamlKeyFile, constants.SAMLKeyFile)
	viper.SetDefault(config.SamlCommonName, constants.DefaultSAMLCN)
	viper.SetDefault(config.SamlIssuer, constants.DefaultSAMLCertIssuer)
	viper.SetDefault(config.SamlValiditySeconds, constants.DefaultSAMLCertValidity)

	viper.SetDefault(config.FlavorSigningCertFile, constants.FlavorSigningCertFile)
	viper.SetDefault(config.FlavorSigningKeyFile, constants.FlavorSigningKeyFile)
	viper.SetDefault(config.FlavorSigningCommonName, constants.DefaultFlavorSigningCN)

	viper.SetDefault(config.PrivacyCaCertFile, constants.PrivacyCACertFile)
	viper.SetDefault(config.PrivacyCaKeyFile, constants.PrivacyCAKeyFile)
	viper.SetDefault(config.PrivacyCaCommonName, constants.DefaultPrivacyCACN)
	viper.SetDefault(config.PrivacyCaIssuer, constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault(config.PrivacyCaValidityYears, constants.DefaultSelfSignedCertValidityYears)

	viper.SetDefault(config.EndorsementCaCertFile, constants.SelfEndorsementCACertFile)
	viper.SetDefault(config.EndorsementCaKeyFile, constants.EndorsementCAKeyFile)
	viper.SetDefault(config.EndorsementCaCommonName, constants.DefaultEndorsementCACN)
	viper.SetDefault(config.EndorsementCaIssuer, constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault(config.EndorsementCaValidityYears, constants.DefaultSelfSignedCertValidityYears)

	viper.SetDefault(config.TagCaCertFile, constants.TagCACertFile)
	viper.SetDefault(config.TagCaKeyFile, constants.TagCAKeyFile)
	viper.SetDefault(config.TagCaCommonName, constants.DefaultTagCACN)
	viper.SetDefault(config.TagCaIssuer, constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault(config.TagCaValidityYears, constants.DefaultSelfSignedCertValidityYears)

	// set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogEntryMaxlength)
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, "info")

	// set default for audit log
	viper.SetDefault(config.AuditLogMaxRowCount, constants.DefaultMaxRowCount)
	viper.SetDefault(config.AuditLogNumRotated, constants.DefaultNumRotated)
	viper.SetDefault(config.AuditLogBufferSize, constants.DefaultChannelBufferSize)

	// set default value for aik
	viper.SetDefault(config.AikCertValidity, constants.DefaultAikCertificateValidity)

	//set default value for Aik Provisioning On EKCert Check
	viper.SetDefault(config.RequireEKCertForHostProvision, false)

	//set default value for Quote Verify For Registration
	viper.SetDefault(config.VerifyQuoteForHostRegistration, false)

	// set default values for server
	viper.SetDefault(commConfig.ServerPort, constants.DefaultHVSListenerPort)
	viper.SetDefault(commConfig.ServerReadTimeout, constants.DefaultReadTimeout)
	viper.SetDefault(commConfig.ServerReadHeaderTimeout, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(commConfig.ServerWriteTimeout, constants.DefaultWriteTimeout)
	viper.SetDefault(commConfig.ServerIdleTimeout, constants.DefaultIdleTimeout)
	viper.SetDefault(commConfig.ServerMaxHeaderBytes, constants.DefaultMaxHeaderBytes)

	// set default for database ssl certificate
	viper.SetDefault(commConfig.DbVendor, "postgres")
	viper.SetDefault(commConfig.DbHost, "localhost")
	viper.SetDefault(commConfig.DbPort, "5432")
	viper.SetDefault(commConfig.DbName, "hvs_db")
	viper.SetDefault(commConfig.DbSslMode, constants.SslModeVerifyFull)
	viper.SetDefault(commConfig.DbSslCert, constants.ConfigDir+"hvsdbsslcert.pem")
	viper.SetDefault(commConfig.DbConnRetryAttempts, constants.DefaultDbConnRetryAttempts)
	viper.SetDefault(commConfig.DbConnRetryTime, constants.DefaultDbConnRetryTime)

	// set default for fvs
	viper.SetDefault(constants.FvsNumberOfVerifiers, constants.DefaultFvsNumberOfVerifiers)
	viper.SetDefault(constants.FvsNumberOfDataFetchers, constants.DefaultFvsNumberOfDataFetchers)
	viper.SetDefault(constants.FvsSkipFlavorSignatureVerification, constants.DefaultSkipFlavorSignatureVerification)
	viper.SetDefault(constants.FvsHostTrustCacheThreshold, constants.DefaultHostTrustCacheThreshold)

	viper.SetDefault(constants.HrrsRefreshPeriod, hrrs.DefaultRefreshPeriod)

	viper.SetDefault(constants.VcssRefreshPeriod, constants.DefaultVcssRefreshPeriod)
}

func defaultConfig() *config.Configuration {
	// support old hvs env
	loadAlias()
	return &config.Configuration{
		AASApiUrl:                      viper.GetString(commConfig.AasBaseUrl),
		CMSBaseURL:                     viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest:               viper.GetString(commConfig.CmsTlsCertSha384),
		Dek:                            viper.GetString(config.DataEncryptionKey),
		AikCertValidity:                viper.GetInt(config.AikCertValidity),
		RequireEKCertForHostProvision:  viper.GetBool(config.RequireEKCertForHostProvision),
		VerifyQuoteForHostRegistration: viper.GetBool(config.VerifyQuoteForHostRegistration),
		AuditLog: config.AuditLogConfig{
			MaxRowCount: viper.GetInt(config.AuditLogMaxRowCount),
			NumRotated:  viper.GetInt(config.AuditLogNumRotated),
			BufferSize:  viper.GetInt(config.AuditLogBufferSize),
		},
		HVS: commConfig.ServiceConfig{
			Username: viper.GetString(config.HvsServiceUsername),
			Password: viper.GetString(config.HvsServicePassword),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
		},
		SAML: config.SAMLConfig{
			CommonConfig: commConfig.SigningCertConfig{
				CertFile:   viper.GetString(config.SamlCertFile),
				KeyFile:    viper.GetString(config.SamlKeyFile),
				CommonName: viper.GetString(config.SamlCommonName),
			},
			Issuer:          viper.GetString(config.SamlIssuer),
			ValiditySeconds: viper.GetInt(config.SamlValiditySeconds),
		},
		FlavorSigning: commConfig.SigningCertConfig{
			CertFile:   viper.GetString(config.FlavorSigningCertFile),
			KeyFile:    viper.GetString(config.FlavorSigningKeyFile),
			CommonName: viper.GetString(config.FlavorSigningCommonName),
		},
		PrivacyCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString(config.PrivacyCaCertFile),
			KeyFile:      viper.GetString(config.PrivacyCaKeyFile),
			CommonName:   viper.GetString(config.PrivacyCaCommonName),
			Issuer:       viper.GetString(config.PrivacyCaIssuer),
			ValidityDays: viper.GetInt(config.PrivacyCaValidityYears),
		},
		EndorsementCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString(config.EndorsementCaCertFile),
			KeyFile:      viper.GetString(config.EndorsementCaKeyFile),
			CommonName:   viper.GetString(config.EndorsementCaCommonName),
			Issuer:       viper.GetString(config.EndorsementCaIssuer),
			ValidityDays: viper.GetInt(config.EndorsementCaValidityYears),
		},
		TagCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString(config.TagCaCertFile),
			KeyFile:      viper.GetString(config.TagCaKeyFile),
			CommonName:   viper.GetString(config.TagCaCommonName),
			Issuer:       viper.GetString(config.TagCaIssuer),
			ValidityDays: viper.GetInt(config.TagCaValidityYears),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt(commConfig.LogMaxLength),
			EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
			Level:        viper.GetString(commConfig.LogLevel),
		},
		HRRS: hrrs.HRRSConfig{
			RefreshPeriod: viper.GetDuration(constants.HrrsRefreshPeriod),
		},
		VCSS: config.VCSSConfig{
			RefreshPeriod: viper.GetDuration(constants.VcssRefreshPeriod),
		},
		FVS: config.FVSConfig{
			NumberOfVerifiers:               viper.GetInt(constants.FvsNumberOfVerifiers),
			NumberOfDataFetchers:            viper.GetInt(constants.FvsNumberOfDataFetchers),
			SkipFlavorSignatureVerification: viper.GetBool(constants.FvsSkipFlavorSignatureVerification),
			HostTrustCacheThreshold:         viper.GetInt(constants.FvsHostTrustCacheThreshold),
		},
		EnableEkCertRevokeChecks: viper.GetBool(constants.EnableEKCertRevokeCheck),
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.DbHost:                  "HVS_DB_HOSTNAME",
		commConfig.DbVendor:                "HVS_DB_VENDOR",
		commConfig.DbPort:                  "HVS_DB_PORT",
		commConfig.DbName:                  "HVS_DB_NAME",
		commConfig.DbUsername:              "HVS_DB_USERNAME",
		commConfig.DbPassword:              "HVS_DB_PASSWORD",
		commConfig.DbSslCert:               "HVS_DB_SSLCERT",
		commConfig.DbSslCertSource:         "HVS_DB_SSLCERTSRC",
		commConfig.DbSslMode:               "HVS_DB_SSL_MODE",
		commConfig.TlsSanList:              "SAN_LIST",
		commConfig.AasBaseUrl:              "AAS_API_URL",
		commConfig.ServerReadTimeout:       "HVS_SERVER_READ_TIMEOUT",
		commConfig.ServerReadHeaderTimeout: "HVS_SERVER_READ_HEADER_TIMEOUT",
		commConfig.ServerWriteTimeout:      "HVS_SERVER_WRITE_TIMEOUT",
		commConfig.ServerIdleTimeout:       "HVS_SERVER_IDLE_TIMEOUT",
		commConfig.ServerMaxHeaderBytes:    "HVS_SERVER_MAX_HEADER_BYTES",
		config.SamlCertFile:                "SAML_CERT_FILE",
		config.SamlKeyFile:                 "SAML_KEY_FILE",
		config.SamlCommonName:              "SAML_COMMON_NAME",
		config.SamlIssuer:                  "SAML_ISSUER_NAME",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
