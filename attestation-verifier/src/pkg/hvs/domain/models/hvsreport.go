/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"time"
)

type HVSReport struct {
	RowId       int
	ID          uuid.UUID
	HostID      uuid.UUID
	TrustReport hvs.TrustReport
	CreatedAt   time.Time
	Expiration  time.Time
	// Saml is string which is actually xml encoded to string
	Saml string
}
