/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

// TpmEndorsement struct
type TpmEndorsement struct {
	// swagger:strfmt uuid
	RowId int       `json:"-"`
	ID    uuid.UUID `json:"id,omitempty"`
	// swagger:strfmt uuid
	HardwareUUID      uuid.UUID `json:"hardware_uuid"`
	Issuer            string    `json:"issuer,omitempty"`
	Revoked           bool      `json:"revoked,omitempty"`
	Certificate       string    `json:"certificate"`
	Comment           string    `json:"comment,omitempty"`
	CertificateDigest string    `json:"certificate_digest,omitempty"`
}

type TpmEndorsementCollection struct {
	TpmEndorsement []*TpmEndorsement `json:"tpmendorsements"`
	Next           string            `json:"next,omitempty"`
	Previous       string            `json:"prev,omitempty"`
}
