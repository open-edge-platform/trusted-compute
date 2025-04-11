/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package config

import log "github.com/sirupsen/logrus"

// this function is for compatibility with older code
// we should stop using it and switch to having configuration
// read from application structure

var globalConfig *Configuration

func Global() *Configuration {
	var err error
	if globalConfig == nil {
		globalConfig, err = LoadConfiguration()
		if err != nil {
			log.WithError(err).Errorf("Failed to load configuration")
		}
	}
	return globalConfig
}
