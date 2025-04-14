/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	PrivacyCA       = ConfigDir + "privacy-ca.cer"
	NatsCredentials = ConfigDir + "credentials/trust-agent.creds"
	VarDir          = InstallationDir + "var/"
	AikCert         = ConfigDir + "aik.pem"
)

const (
	TlsKey                          = "tls"
	InstallationDir                 = "/opt/trustagent/"
	ConfigDir                       = "/opt/trustagent/"
	ConfigFileName                  = "config"
	ConfigFilePath                  = ConfigDir + ConfigFileName + ".yml"
	ExecLinkPath                    = "/usr/bin/tagent"
	LogDir                          = "/var/log/trustagent/"
	HttpLogFile                     = LogDir + "http.log"
	DefaultLogFilePath              = LogDir + "trustagent.log"
	SecurityLogFilePath             = LogDir + "trustagent-security.log"
	TLSCertFilePath                 = ConfigDir + "tls-cert.pem"
	TLSKeyFilePath                  = ConfigDir + "tls-key.pem"
	ConstVarDir                     = InstallationDir + "var/"
	RamfsDir                        = ConstVarDir + "ramfs/"
	SystemInfoDir                   = ConstVarDir + "system-info/"
	PlatformInfoFilePath            = SystemInfoDir + "platform-info"
	MeasureLogFilePath              = ConstVarDir + "measure-log.json"
	BindingKeyCertificatePath       = "/opt/workload-agent/bindingkey.pem"
	TBootXmMeasurePath              = "/opt/tbootxm/bin/measure"
	DevMemFilePath                  = "/dev/mem"
	Tpm2FilePath                    = "/sys/firmware/acpi/tables/TPM2"
	AppEventFilePath                = RamfsDir + "pcr_event_log"
	RootUserName                    = "root"
	TagentUserName                  = "tagent"
	DefaultPort                     = 1443
	ApiVersion                      = "v2"
	FlavorUUIDs                     = "FLAVOR_UUIDS"
	DefaultLogEntryMaxlength        = 3000
	DefaultLogStdOutEnable          = true
	DefaultLogLevel                 = "info"
	FlavorLabels                    = "FLAVOR_LABELS"
	ServiceName                     = "tagent.service"
	ExplicitServiceName             = "Trust Agent"
	TAServiceName                   = "TA"
	ServiceStatusCommand            = "systemctl status " + ServiceName
	ServiceStopCommand              = "systemctl stop " + ServiceName
	ServiceStartCommand             = "systemctl start " + ServiceName
	ServiceDisableCommand           = "systemctl disable " + ServiceName
	ServiceDisableInitCommand       = "systemctl disable tagent_init.service"
	UninstallTbootXmScript          = "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
	TrustedJWTSigningCertsDir       = ConfigDir + "jwt/"
	TrustedCaCertsDir               = ConfigDir + "cacerts/"
	DefaultKeyAlgorithm             = "rsa"
	DefaultKeyAlgorithmLength       = 3072
	JWTCertsCacheTime               = "1m"
	DefaultTaTlsCn                  = "Trust Agent TLS Certificate"
	DefaultTaTlsSan                 = "127.0.0.1,localhost"
	DefaultTaTlsSanSeparator        = ","
	FlavorUUIDMaxLength             = 500
	FlavorLabelsMaxLength           = 500
	DefaultReadTimeout              = 30 * time.Second
	DefaultReadHeaderTimeout        = 10 * time.Second
	DefaultWriteTimeout             = 10 * time.Second
	DefaultIdleTimeout              = 10 * time.Second
	DefaultMaxHeaderBytes           = 1 << 20
	TagIndexSize                    = 48 // size of sha384 hash
	CommunicationModeHttp           = "http"
	CommunicationModeOutbound       = "outbound"
	DefaultApiTokenExpiration       = 31536000
	DefaultAsyncReportRetryInterval = 5
	VerificationServiceName         = "HVS"
	ImaConfigsDir                   = "/opt/ima-configs/"
	ImaPolicyPath                   = ImaConfigsDir + "ima_policy"
	ImaAllowlistPath                = ImaConfigsDir + "ima_allowlist"
)

// Env Variables
const (
	EnvTPMOwnerSecret            = "TPM_OWNER_SECRET"
	EnvTPMEndorsementSecret      = "TPM_ENDORSEMENT_SECRET"
	EnvVSAPIURL                  = "HVS_URL"
	EnvTAPort                    = "TRUSTAGENT_PORT"
	EnvAASBaseURL                = "AAS_API_URL"
	EnvCertSanList               = "SAN_LIST"
	EnvCurrentIP                 = "CURRENT_IP"
	EnvBearerToken               = "BEARER_TOKEN"
	EnvLogEntryMaxlength         = "LOG_ENTRY_MAXLENGTH"
	EnvTALogLevel                = "TRUSTAGENT_LOG_LEVEL"
	EnvTALogEnableConsoleLog     = "TA_ENABLE_CONSOLE_LOG"
	EnvTAServerReadTimeout       = "TA_SERVER_READ_TIMEOUT"
	EnvTAServerReadHeaderTimeout = "TA_SERVER_READ_HEADER_TIMEOUT"
	EnvTAServerWriteTimeout      = "TA_SERVER_WRITE_TIMEOUT"
	EnvTAServerIdleTimeout       = "TA_SERVER_IDLE_TIMEOUT"
	EnvTAServerMaxHeaderBytes    = "TA_SERVER_MAX_HEADER_BYTES"
	EnvTAServiceMode             = "TA_SERVICE_MODE"
	EnvNATServers                = "NATS_SERVERS"
	EnvTAHostId                  = "TA_HOST_ID"
	EnvServiceUser               = "SERVICE_USERNAME"
	EnvServicePassword           = "SERVICE_PASSWORD"
	EnvFlavorUUIDs               = "FLAVOR_UUIDS"
	EnvFlavorLabels              = "FLAVOR_LABELS"
	EnvIMAMeasureEnabled         = "IMA_MEASURE_ENABLED"
)

// "TODO" comment -- the SHA constants should live in intel-secl/pkg/model/
type SHAAlgorithm string

const (
	SHA1    SHAAlgorithm = "SHA1"
	SHA256  SHAAlgorithm = "SHA256"
	SHA384  SHAAlgorithm = "SHA384"
	SHA512  SHAAlgorithm = "SHA512"
	UNKNOWN SHAAlgorithm = "unknown"
)

// Setup task constants
const (
	DefaultSetupCommand                    = "all"
	DownloadRootCACertCommand              = "download-ca-cert"
	DownloadCertCommand                    = "download-cert"
	TakeOwnershipCommand                   = "take-ownership"
	ProvisionAttestationIdentityKeyCommand = "provision-aik"
	DownloadPrivacyCACommand               = "download-privacy-ca"
	ProvisionPrimaryKeyCommand             = "provision-primary-key"
	CreateHostCommand                      = "create-host"
	CreateHostUniqueFlavorCommand          = "create-host-unique-flavor"
	GetConfiguredManifestCommand           = "get-configured-manifest"
	ProvisionAttestationCommand            = "provision-attestation"
	UpdateCertificatesCommand              = "update-certificates"
	UpdateServiceConfigCommand             = "update-service-config"
	DefineTagIndexCommand                  = "define-tag-index"
	DownloadCredentialCommand              = "download-credential"
	DownloadApiTokenCommand                = "download-api-token"
)

const (
	SystemctlStart  = "start"
	SystemctlStop   = "stop"
	SystemctlStatus = "status"
)

// viper config keys
const (
	CmsBaseUrlViperKey              = "cms.base-url"
	CmsTlsCertSha384ViperKey        = "cms.tls-cert-sha384"
	TlsCommonNameViperKey           = "tls.common-name"
	TlsSanListViperKey              = "tls.san-list"
	BearerTokenViperKey             = "bearer-token"
	AasBaseUrlViperKey              = "aas-base-url"
	ServerPortViperKey              = "server.port"
	ServerReadTimeoutViperKey       = "server.read-timeout"
	ServerReadHeaderTimeoutViperKey = "server.read-header-timeout"
	ServerWriteTimeoutViperKey      = "server.write-timeout"
	ServerIdleTimeoutViperKey       = "server.idle-timeout"
	ServerMaxHeaderBytesViperKey    = "server.max-header-bytes"
	NatsServersViperKey             = "nats-servers"
	HvsUrlViperKey                  = "hvs-url"
	TpmOwnerSecretViperKey          = "tpm-owner-secret"
	TpmEndorsementSecretViperKey    = "tpm-endorsement-secret"
	NatsTaHostIdViperKey            = "nats-host-id"
	TaServiceModeViperKey           = "ta-service-mode"
	TaLogLevelViperKey              = "log.level"
	LogEnableStdoutViperKey         = "log.enable-stdout"
	LogEntryMaxLengthViperKey       = "log.max-length"
	ViperKeyDashSeparator           = "-"
	ViperDotSeparator               = "."
	EnvNameSeparator                = "_"
	ImaMeasureEnabled               = "ima-measure-enabled"
)

// IMA Log constants
const (
	ImaHashSha1   = "ima_hash=sha1"
	ImaHashSha256 = "ima_hash=sha256"
	ImaHashSha512 = "ima_hash=sha512"
	ImaPolicyTCB  = "ima_policy=tcb"
	PCR10         = 10
	TemplateNG    = "ima_template=ima-ng"
	TemplateSIG   = "ima_template=ima-sig"
	TemplateIMA   = "ima_template=ima"
)

var (
	AsciiRuntimeMeasurementFilePath = "/opt/ima/ascii_runtime_measurements"
	ProcFilePath                    = "/opt/ima_policy"
)
