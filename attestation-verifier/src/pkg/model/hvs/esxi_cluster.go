/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

type ESXiClusterCollection struct {
	ESXiCluster []ESXiCluster `json:"esxi_clusters"`
	Next        string        `json:"next,omitempty"`
	Previous    string        `json:"prev,omitempty"`
}

type ESXiCluster struct {
	// swagger:strfmt uuid
	Id               uuid.UUID `json:"id"`
	RowId            int       `json:"-"`
	ConnectionString string    `json:"connection_string"`
	ClusterName      string    `json:"cluster_name"`
	HostNames        []string  `json:"hosts,omitempty"`
}

type ESXiClusterCreateRequest struct {
	ConnectionString string `json:"connection_string"`
	ClusterName      string `json:"cluster_name"`
}
