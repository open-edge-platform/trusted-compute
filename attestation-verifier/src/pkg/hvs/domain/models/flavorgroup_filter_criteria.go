/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

type FlavorGroupFilterCriteria struct {
	Ids          []uuid.UUID
	FlavorId     *uuid.UUID
	NameEqualTo  string
	NameContains string
	Limit        int
	AfterId      int
}
