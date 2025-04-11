/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

//Certificate stores the decoded certificate values
type Certificate struct {
	// swagger:strfmt uuid
	ID uuid.UUID `json:"id,omitempty"`
	// swagger:strfmt base64
	Certificate []byte     `json:"certificate"`
	Subject     string     `json:"subject,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Revoked     bool       `json:"revoked"`
	Digest      string     `json:"digest,omitempty"`
}
