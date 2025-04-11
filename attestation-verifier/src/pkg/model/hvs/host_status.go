/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"time"

	"github.com/google/uuid"
)

// HostStatusInformation holds the current connection state between the Host's Trust Agent and VS and the timestamp of the
// last successful connection
type HostStatusInformation struct {
	// swagger:strfmt string
	HostState         HostState `json:"host_state"`
	LastTimeConnected time.Time `json:"last_time_connected"`
}

// HostStatus contains the response for the Host Status API for an individual host
type HostStatus struct {
	RowId int       `json:"-"`
	ID    uuid.UUID `json:"id"`
	// swagger:strfmt uuid
	HostID                uuid.UUID             `json:"host_id"`
	Created               time.Time             `json:"created"`
	HostStatusInformation HostStatusInformation `json:"status"`
	HostManifest          HostManifest          `json:"host_manifest"`
}

// HostStatusCollection holds a collection of HostStatus in response to an API query
type HostStatusCollection struct {
	HostStatuses []HostStatus `json:"host_status" xml:"host_status"`
	Next         string       `json:"next,omitempty" xml:"next"`
	Previous     string       `json:"prev,omitempty" xml:"prev"`
}
