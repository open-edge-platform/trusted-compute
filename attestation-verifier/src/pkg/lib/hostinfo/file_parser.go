/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bufio"
	"os"
	"strings"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type fileInfoParser struct{}

func (fileInfoParser *fileInfoParser) Init() error {
	return nil
}

func (fileInfoParser *fileInfoParser) Parse(hostInfo *model.HostInfo) error {

	err := fileInfoParser.parseHostName(hostInfo)
	if err != nil {
		log.Errorf("Failed to parse hostname: %+v", err)
	}

	if _, err := os.Stat(isDockerFile); err == nil {
		hostInfo.IsDockerEnvironment = true
	}

	if _, err := os.Stat(isOCIContainerFile); err == nil {
		hostInfo.IsDockerEnvironment = true
	}

	if _, err := os.Stat(isEFIBootFile); err == nil {
		hostInfo.HardwareFeatures.UEFI = &model.UEFI{
			HardwareFeature: model.HardwareFeature{Enabled: true},
		}
	}

	return nil
}

func (fileInfoParser *fileInfoParser) parseHostName(hostInfo *model.HostInfo) error {

	if _, err := os.Stat(hostNameFile); os.IsNotExist(err) {
		return errors.Wrapf(err, "Could not find hostname file %q", hostNameFile)
	}

	file, err := os.Open(hostNameFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to open hostname file %q", hostNameFile)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Errorf("Failed close hostname file %q: %s", hostNameFile, err.Error())
		}
	}()

	lineReader := bufio.NewReader(file)
	hostInfo.HostName, err = lineReader.ReadString('\n')
	if err != nil {
		return errors.Wrapf(err, "Failed to read hostname file %q", hostNameFile)
	}

	// trim any line feeds
	hostInfo.HostName = strings.ReplaceAll(hostInfo.HostName, "\n", "")

	return nil
}
