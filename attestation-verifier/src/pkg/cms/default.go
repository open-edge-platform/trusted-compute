/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault(config.TlsSanList, constants.DefaultTlsSan)

	// set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogEntryMaxlength)
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, "info")

	// set default values for server
	viper.SetDefault(commConfig.ServerPort, constants.DefaultPort)
	viper.SetDefault(commConfig.ServerReadTimeout, constants.DefaultReadTimeout)
	viper.SetDefault(commConfig.ServerReadHeaderTimeout, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(commConfig.ServerWriteTimeout, constants.DefaultWriteTimeout)
	viper.SetDefault(commConfig.ServerIdleTimeout, constants.DefaultIdleTimeout)
	viper.SetDefault(commConfig.ServerMaxHeaderBytes, constants.DefaultMaxHeaderBytes)

	viper.SetDefault(config.CACertValidity, constants.DefaultCACertValidity)
	viper.SetDefault(config.CACertOrganization, constants.DefaultOrganization)
	viper.SetDefault(config.CACertLocality, constants.DefaultLocality)
	viper.SetDefault(config.CACertProvince, constants.DefaultProvince)
	viper.SetDefault(config.CACertCountry, constants.DefaultCountry)

	viper.SetDefault(config.AasTlsCn, constants.DefaultAasTlsCn)
	viper.SetDefault(config.AasJwtCn, constants.DefaultAasJwtCn)
	viper.SetDefault(config.AasTlsSan, constants.DefaultTlsSan)

	viper.SetDefault(config.TokenDurationMins, constants.DefaultTokenDurationMins)
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt(commConfig.LogMaxLength),
			EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
			Level:        viper.GetString(commConfig.LogLevel),
		},
		AasJwtCn:   viper.GetString(config.AasJwtCn),
		AasTlsCn:   viper.GetString(config.AasTlsCn),
		AasTlsSan:  viper.GetString(config.AasTlsSan),
		TlsSanList: viper.GetString(config.TlsSanList),
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.ServerReadTimeout:       "CMS_SERVER_READ_TIMEOUT",
		commConfig.ServerReadHeaderTimeout: "CMS_SERVER_READ_HEADER_TIMEOUT",
		commConfig.ServerWriteTimeout:      "CMS_SERVER_WRITE_TIMEOUT",
		commConfig.ServerIdleTimeout:       "CMS_SERVER_IDLE_TIMEOUT",
		commConfig.ServerMaxHeaderBytes:    "CMS_SERVER_MAX_HEADER_BYTES",
		commConfig.LogEnableStdout:         "CMS_ENABLE_CONSOLE_LOG",
		commConfig.AasBaseUrl:              "AAS_API_URL",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
