/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

// KeyInformation - Contains required key related attributes for key create or register request.
type KeyInformation struct {
	// swagger:strfmt uuid
	ID        uuid.UUID `json:"id,omitempty"`
	Algorithm string    `json:"algorithm"`
	KeyLength int       `json:"key_length,omitempty"`
	CurveType string    `json:"curve_type,omitempty"`
	KeyString string    `json:"key_string,omitempty"`
	KmipKeyID string    `json:"kmip_key_id,omitempty"`
}

// KeyRequest - All required attributes for key create or register request.
type KeyRequest struct {
	KeyInformation *KeyInformation `json:"key_information"`
	// swagger:strfmt uuid
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
	Label            string    `json:"label,omitempty"`
	Usage            string    `json:"usage,omitempty"`
}

// KeyResponse - key attributes from key create or register response.
type KeyResponse struct {
	KeyInformation *KeyInformation `json:"key_information"`
	// swagger:strfmt uuid
	TransferPolicyID uuid.UUID `json:"transfer_policy_id"`
	TransferLink     string    `json:"transfer_link"`
	CreatedAt        time.Time `json:"created_at"`
	Label            string    `json:"label,omitempty"`
	Usage            string    `json:"usage,omitempty"`
}

// KeyTransferAttributes - Contains all possible key transfer attributes.
type KeyTransferAttributes struct {
	// swagger:strfmt uuid
	KeyId uuid.UUID `json:"id,omitempty"`
	// swagger:strfmt base64
	KeyData      string     `json:"payload,omitempty"`
	KeyAlgorithm string     `json:"algorithm,omitempty"`
	KeyLength    int        `json:"key_length,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	Policy       struct {
		Link struct {
			KeyTransfer struct {
				Href   string `json:"href,omitempty"`
				Method string `json:"method,omitempty"`
			} `json:"key-transfer,omitempty"`
		} `json:"link,omitempty"`
	} `json:"policy,omitempty"`
}
