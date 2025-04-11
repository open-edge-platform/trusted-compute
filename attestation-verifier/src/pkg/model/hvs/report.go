/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"time"

	"github.com/google/uuid"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

type ReportCollection struct {
	Reports  []*Report `json:"reports" xml:"reports"`
	Next     string    `json:"next,omitempty" xml:"next"`
	Previous string    `json:"prev,omitempty" xml:"prev"`
}

type Report struct {
	// swagger:strfmt uuid
	RowId            int              `json:"-"`
	ID               uuid.UUID        `json:"id"`
	TrustInformation TrustInformation `json:"trust_information"`
	// swagger:strfmt uuid
	HostID      uuid.UUID        `json:"host_id"`
	TrustReport TrustReport      `json:"-"`
	Saml        string           `json:"-"`
	HostInfo    taModel.HostInfo `json:"host_info"`
	CreatedAt   time.Time        `json:"created"`
	Expiration  time.Time        `json:"expiration"`
}

type TrustInformation struct {
	Overall     bool                                 `json:"OVERALL"`
	FlavorTrust map[FlavorPartName]FlavorTrustStatus `json:"flavors_trust"`
}

type FlavorTrustStatus struct {
	Trust                bool         `json:"trust"`
	RuleResultCollection []RuleResult `json:"rules"`
}

type ReportCreateRequest struct {
	// swagger:strfmt uuid
	HostID uuid.UUID `json:"host_id"`
	// swagger:strfmt uuid
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
	HostName     string    `json:"host_name"`
}
