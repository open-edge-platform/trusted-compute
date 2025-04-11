/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"os"
	"strings"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// values for webservice connections
	viper.SetDefault(constants.TaServiceModeViperKey, constants.CommunicationModeHttp)
	viper.SetDefault(constants.ServerPortViperKey, constants.DefaultPort)
	viper.SetDefault(constants.ServerReadTimeoutViperKey, constants.DefaultReadTimeout)
	viper.SetDefault(constants.ServerReadHeaderTimeoutViperKey, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(constants.ServerWriteTimeoutViperKey, constants.DefaultWriteTimeout)
	viper.SetDefault(constants.ServerIdleTimeoutViperKey, constants.DefaultIdleTimeout)
	viper.SetDefault(constants.ServerMaxHeaderBytesViperKey, constants.DefaultMaxHeaderBytes)

	// logging defaults
	viper.SetDefault(constants.TaLogLevelViperKey, constants.DefaultLogLevel)
	viper.SetDefault(constants.LogEnableStdoutViperKey, constants.DefaultLogStdOutEnable)
	viper.SetDefault(constants.LogEntryMaxLengthViperKey, constants.DefaultLogEntryMaxlength)

	viper.SetDefault(constants.TlsSanListViperKey, constants.DefaultTaTlsSan)
	viper.SetDefault(constants.TlsCommonNameViperKey, constants.DefaultTaTlsCn)

	// nats
	viper.SetDefault(constants.NatsServersViperKey, nil)
	hostName, _ := os.Hostname()
	viper.SetDefault(constants.NatsTaHostIdViperKey, hostName)

	// ima
	viper.SetDefault(constants.ImaMeasureEnabled, true)
}

func loadAlias() {
	alias := map[string]string{
		constants.TlsSanListViperKey:           constants.EnvCertSanList,
		constants.AasBaseUrlViperKey:           constants.EnvAASBaseURL,
		constants.ServerReadTimeoutViperKey:    constants.EnvTAServerReadTimeout,
		constants.EnvTAServerReadHeaderTimeout: constants.EnvTAServerReadHeaderTimeout,
		constants.ServerWriteTimeoutViperKey:   constants.EnvTAServerWriteTimeout,
		constants.ServerIdleTimeoutViperKey:    constants.EnvTAServerIdleTimeout,
		constants.ServerMaxHeaderBytesViperKey: constants.EnvTAServerMaxHeaderBytes,
		constants.NatsTaHostIdViperKey:         constants.EnvTAHostId,
		constants.ImaMeasureEnabled:            constants.EnvIMAMeasureEnabled,
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}

func defaultConfig() *config.TrustAgentConfiguration {
	loadAlias()
	return &config.TrustAgentConfiguration{
		Mode: viper.GetString(constants.TaServiceModeViperKey),
		Logging: commConfig.LogConfig{
			Level:        viper.GetString(constants.TaLogLevelViperKey),
			EnableStdout: viper.GetBool(constants.LogEnableStdoutViperKey),
			MaxLength:    viper.GetInt(constants.LogEntryMaxLengthViperKey),
		},
		Server: commConfig.ServerConfig{
			Port:              viper.GetInt(constants.ServerPortViperKey),
			ReadTimeout:       viper.GetDuration(constants.ServerReadTimeoutViperKey),
			ReadHeaderTimeout: viper.GetDuration(constants.ServerReadHeaderTimeoutViperKey),
			WriteTimeout:      viper.GetDuration(constants.ServerWriteTimeoutViperKey),
			IdleTimeout:       viper.GetDuration(constants.ServerIdleTimeoutViperKey),
			MaxHeaderBytes:    viper.GetInt(constants.ServerMaxHeaderBytesViperKey),
		},
		HVS: config.HvsConfig{
			Url: viper.GetString(constants.HvsUrlViperKey),
		},
		Aas: config.AasConfig{BaseURL: viper.GetString(constants.AasBaseUrlViperKey)},
		Cms: config.CmsConfig{
			BaseURL:       viper.GetString(constants.CmsBaseUrlViperKey),
			TLSCertDigest: viper.GetString(constants.CmsTlsCertSha384ViperKey),
		},
		Tls: config.TlsConfig{
			SANList:    viper.GetString(constants.TlsSanListViperKey),
			CommonName: viper.GetString(constants.TlsCommonNameViperKey),
		},
		Nats: config.NatsService{
			Servers: strings.Split(viper.GetString(constants.NatsServersViperKey), constants.DefaultTaTlsSanSeparator),
			HostID:  viper.GetString(constants.NatsTaHostIdViperKey),
		},
		ImaMeasureEnabled: viper.GetBool(constants.ImaMeasureEnabled),
	}
}
