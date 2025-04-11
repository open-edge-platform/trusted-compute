/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

import "time"

// 2 things done on this file:
//   1. remove unused constants that does not have clear meaning
//   2. categorize stuffs

// general HVS constants
const (
	ServiceName         = "HVS"
	ExplicitServiceName = "Host Verification Service"
	ServiceDir          = "hvs/"
	OldServiceName      = "mtwilson"
	ApiVersion          = "/v2"
	ServiceUserName     = "hvs"

	// Timestamp operations
	ParamDateFormat        = "2006-01-02"
	ParamDateTimeFormat    = "2006-01-02 15:04:05"
	ParamDateTimeFormatUTC = "2006-01-02T15:04:05.000Z"

	// service remove command
	ServiceRemoveCmd = "systemctl disable hvs"
)

// these are used only when uninstalling service
const (
	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir
)

// file and directory constants
const (
	ConfigDir             = "/etc/hvs/"
	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	TrustedRootCACertsDir     = TrustedCaCertsDir + "root/"

	TrustedKeysDir = ConfigDir + "trusted-keys/"

	// NatsCredentials path
	NatsCredentials = ConfigDir + "credentials/isecl-hvs.creds"

	// saml key and cert
	SAMLCertFile = TrustedCaCertsDir + "saml-cert.pem"
	SAMLKeyFile  = TrustedKeysDir + "saml.key"

	// flavor signing key and cert
	FlavorSigningCertFile = TrustedCaCertsDir + "flavor-signing.pem"
	FlavorSigningKeyFile  = TrustedKeysDir + "flavor-signing.key"

	// privacy ca key and cert
	PrivacyCACertFile = TrustedCaCertsDir + "privacy-ca/privacy-ca-cert.pem"
	PrivacyCAKeyFile  = TrustedKeysDir + "privacy-ca.key"

	//TODO remove or dont use temporary files
	AikRequestsDir            = HomeDir + "privacyca-aik-requests/"
	EndorsementCACertDir      = ConfigDir + "certs/endorsement/"
	EndorsementCACertFile     = EndorsementCACertDir + "EndorsementCA-external.pem" //External ECA
	SelfEndorsementCACertFile = EndorsementCACertDir + "EndorsementCA.pem"          //Self signed ECA
	EndorsementCAKeyFile      = TrustedKeysDir + "endorsement-ca.key"

	TagCACertFile = TrustedCaCertsDir + "tag-ca-cert.pem"
	TagCAKeyFile  = TrustedKeysDir + "tag-ca.key"

	// default locations for tls certificate and key
	DefaultTLSKeyFile  = ConfigDir + "tls.key"
	DefaultTLSCertFile = ConfigDir + "tls-cert.pem"
)

// tls constants
const (
	DefaultHvsTlsCn     = "HVS TLS Certificate"
	DefaultHvsTlsSan    = "127.0.0.1,localhost"
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072
)

// aik and privacy ca constants
const (
	DefaultAikCertificateValidity  = 5
	DefaultPrivacyCACertValidity   = 5
	HostSigningKeyCertificateCN    = "Signing_Key_Certificate"
	HostBindingKeyCertificateCN    = "Binding_Key_Certificate"
	DefaultPrivacyCaIdentityIssuer = "hvs-pca-aik"
)

// general constants for certificates
const (
	DefaultSAMLCN           = "HVS SAML Certificate"
	DefaultSAMLCertIssuer   = "AttestationService"
	DefaultSAMLCertValidity = 86400

	DefaultFlavorSigningCN = "HVS Flavor Signing Certificate"
	DefaultPrivacyCACN     = "HVS Privacy Certificate"
	DefaultEndorsementCACN = "HVS Endorsement Certificate"
	DefaultTagCACN         = "HVS Tag Certificate"

	DefaultSelfSignedCertIssuer        = "intel-secl"
	DefaultSelfSignedCertValidityYears = 5

	DefaultCertIssuer = "HVS Default Issuer"
	DefaultCN         = "HVS Default Common Name"

	DefaultTagCertValiditySeconds = 60 * 60 * 24 * 365
)

// server constants
const (
	DefaultHVSListenerPort   = 8443
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
)

// db constants
const (
	DBTypePostgres = "postgres"

	DefaultDbConnRetryAttempts  = 4
	DefaultDbConnRetryTime      = 1
	DefaultSearchResultRowLimit = 10000

	//Postgres connection SslModes
	SslModeAllow      = "allow"
	SslModePrefer     = "prefer"
	SslModeVerifyCa   = "verify-ca"
	SslModeRequire    = "require"
	SslModeVerifyFull = "verify-full"
)

// log constants
const (
	DefaultLogEntryMaxlength = 1500
)

// jwt constants
const (
	JWTCertsCacheTime = "1m"
)

// FVS constants
const (
	DefaultFvsNumberOfVerifiers            = 20
	DefaultFvsNumberOfDataFetchers         = 20
	DefaultSkipFlavorSignatureVerification = false
	DefaultHostTrustCacheThreshold         = 100000
)

//VCSS constants
const (
	DefaultVcssRefreshPeriod = time.Duration(2) * time.Minute
)

// audit log constants
const (
	DefaultMaxRowCount       = 10000
	DefaultNumRotated        = 10
	DefaultChannelBufferSize = 5000
)

// Search APIs filter constants
const (
	MaxNumDaysSearchLimit = 365
)

//Schema location constants
const (
	CommonDefinitionsSchema = "/etc/hvs/schema/common.schema.json"
	FlavorTemplateSchema    = "/etc/hvs/schema/flavor-template.json"
)

//Default flavor templates directory
const DefaultFlavorTemplatesDirectory = "/etc/hvs/templates/"

const (
	FvsNumberOfVerifiers               = "fvs-number-of-verifiers"
	FvsNumberOfDataFetchers            = "fvs-number-of-data-fetchers"
	FvsSkipFlavorSignatureVerification = "fvs-skip-flavor-signature-verification"
	FvsHostTrustCacheThreshold         = "fvs-host-trust-cache-threshold"
	HrrsRefreshPeriod                  = "hrrs-refresh-period"
	VcssRefreshPeriod                  = "vcss-refresh-period"
)

// EnableEKCertRevokeCheck
const EnableEKCertRevokeCheck = "enable-ekcert-revoke-check"

//Default checks
const (
	DuplicateKeyCheck     = "duplicate key"
	ErrorGettingFgCheck   = "Error when searching flavor group"
	FgNotFoundCheck       = "Flavor group record not found"
	AuthenticationCheck   = "401"
	InternalServerCheck   = "403"
	TemplateNotFoundCheck = "No templates found"
)

// IMA
const IMAMeasureEnabled = "ima_measure_enabled"
