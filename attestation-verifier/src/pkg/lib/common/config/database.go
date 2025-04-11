/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package config

type DBConfig struct {
	Vendor   string `yaml:"vendor" mapstructure:"vendor"`
	Host     string `yaml:"host" mapstructure:"host"`
	Port     int    `yaml:"port" mapstructure:"port"`
	DBName   string `yaml:"name" mapstructure:"name"`
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
	SSLMode  string `yaml:"ssl-mode" mapstructure:"ssl-mode"`
	SSLCert  string `yaml:"ssl-cert" mapstructure:"ssl-cert"`

	ConnectionRetryAttempts int `yaml:"conn-retry-attempts" mapstructure:"conn-retry-attempts"`
	ConnectionRetryTime     int `yaml:"conn-retry-time" mapstructure:"conn-retry-time"`
}
