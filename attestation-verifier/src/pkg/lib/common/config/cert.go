/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

type SigningCertConfig struct {
	CertFile   string `yaml:"cert-file" mapstructure:"cert-file"`
	KeyFile    string `yaml:"key-file" mapstructure:"key-file"`
	CommonName string `yaml:"common-name" mapstructure:"common-name"`
}

type TLSCertConfig struct {
	CertFile   string `yaml:"cert-file" mapstructure:"cert-file"`
	KeyFile    string `yaml:"key-file" mapstructure:"key-file"`
	CommonName string `yaml:"common-name" mapstructure:"common-name"`
	SANList    string `yaml:"san-list" mapstructure:"san-list"`
}

type SelfSignedCertConfig struct {
	CertFile     string `yaml:"cert-file" mapstructure:"cert-file"`
	KeyFile      string `yaml:"key-file" mapstructure:"key-file"`
	CommonName   string `yaml:"common-name" mapstructure:"common-name"`
	Issuer       string `yaml:"issuer" mapstructure:"issuer"`
	ValidityDays int    `yaml:"validity-years" mapstructure:"validity-years"`
}
