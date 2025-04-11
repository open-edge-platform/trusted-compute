/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package config

import (
	"time"
)

type ServerConfig struct {
	Port int `yaml:"port" mapstructure:"port"`

	ReadTimeout       time.Duration `yaml:"read-timeout" mapstructure:"read-timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read-header-timeout" mapstructure:"read-header-timeout"`
	WriteTimeout      time.Duration `yaml:"write-timeout" mapstructure:"write-timeout"`
	IdleTimeout       time.Duration `yaml:"idle-timeout" mapstructure:"idle-timeout"`
	MaxHeaderBytes    int           `yaml:"max-header-bytes" mapstructure:"max-header-bytes"`
}

type ServiceConfig struct {
	Username string `yaml:"service-username" mapstructure:"service-username"`
	Password string `yaml:"service-password" mapstructure:"service-password"`
}
