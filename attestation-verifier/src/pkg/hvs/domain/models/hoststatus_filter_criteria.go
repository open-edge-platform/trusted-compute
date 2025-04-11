/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
	"time"
)

// HostStatusFilterCriteria holds the filter criteria for the HostStatus resource used by Search HostStatus API
type HostStatusFilterCriteria struct {
	Id             uuid.UUID
	HostId         uuid.UUID
	HostHardwareId uuid.UUID
	HostName       string
	HostStatus     string
	FromDate       time.Time
	ToDate         time.Time
	LatestPerHost  bool
	NumberOfDays   int
	Limit          int
	AfterId        int
}
