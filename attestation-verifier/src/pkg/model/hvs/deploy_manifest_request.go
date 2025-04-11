/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

type DeployManifestRequest struct {
	// swagger:strfmt uuid
	HostId uuid.UUID `json:"host_id"`
	// swagger:strfmt uuid
	FlavorId uuid.UUID `json:"flavor_id"`
}
