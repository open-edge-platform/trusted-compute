/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package models

import "github.com/google/uuid"

type ESXiClusterFilterCriteria struct {
	Id          uuid.UUID
	ClusterName string
	Limit       int
	AfterId     int
}
