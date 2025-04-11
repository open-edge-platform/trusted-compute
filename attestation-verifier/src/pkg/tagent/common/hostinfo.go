/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
)

// GetHostInfo Assuming that the /opt/trustagent/var/system-info/platform-info file has been created
// during startup, this function reads the contents of the json file and returns the corresponding
// HostInfo structure.
func (handler *requestHandlerImpl) GetHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error) {
	var hostInfo *taModel.HostInfo

	hostInfo, err := util.ReadHostInfo(platformInfoFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading host-info file %s", platformInfoFilePath)
	}

	return hostInfo, nil
}
