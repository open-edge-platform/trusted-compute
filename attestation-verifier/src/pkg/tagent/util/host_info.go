/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

func ReadHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error) {
	var hostInfo taModel.HostInfo
	if _, err := os.Stat(platformInfoFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - %s does not exist", message.AppRuntimeErr, platformInfoFilePath)
	}

	jsonData, err := ioutil.ReadFile(platformInfoFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error reading %s", message.AppRuntimeErr, platformInfoFilePath)
	}

	err = json.Unmarshal(jsonData, &hostInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error unmarshalling the hostInfo", message.AppRuntimeErr)
	}
	return &hostInfo, nil
}
