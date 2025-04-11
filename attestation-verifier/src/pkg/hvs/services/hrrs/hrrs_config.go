/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hrrs

import "time"

var (
	// DefaultRefreshPeriod by default check for expired reports every five minutes
	DefaultRefreshPeriod, _ = time.ParseDuration("5m")
)

type HRRSConfig struct {
	// RefreshPeriod determines how frequently the HRRS checks for expired reports (defaults to
	// DefaultRefreshPeriod).
	RefreshPeriod time.Duration `yaml:"refresh-period" mapstructure:"refresh-period"`
}
