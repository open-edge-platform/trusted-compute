/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package config

type LogConfig struct {
	MaxLength    int    `yaml:"max-length" mapstructure:"max-length"`
	EnableStdout bool   `yaml:"enable-stdout" mapstructure:"enable-stdout"`
	Level        string `yaml:"level" mapstructure:"level"`
}
