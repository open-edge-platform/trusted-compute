/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bufio"
	"io"
	"os"
	"strings"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

// osInfoParser collects the HostInfo's OSName and OSVersion fields
// from /etc/os-release file (formatted as described in
// https://www.freedesktop.org/software/systemd/man/os-release.html).
type osInfoParser struct {
	reader io.ReadCloser
}

// Setup the 'ReadCloser' using the file specfied by 'osReleaseFile' which
// defaults to /etc/os-release.
func (osInfoParser *osInfoParser) Init() error {

	var err error

	if _, err := os.Stat(osReleaseFile); os.IsNotExist(err) {
		return errors.Wrapf(err, "Could not find os-release file %q", osReleaseFile)
	}

	osInfoParser.reader, err = os.Open(osReleaseFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to open os-release file %q", osReleaseFile)
	}

	return nil
}

func (osInfoParser *osInfoParser) Parse(hostInfo *model.HostInfo) error {
	var err error

	if osInfoParser.reader == nil {
		return errors.New("The reader has not been initialized")
	}

	defer func() {
		err = osInfoParser.reader.Close()
		if err != nil {
			log.Errorf("Failed close os-release file %q: %+v", osReleaseFile, err)
		}
	}()

	lineReader := bufio.NewReader(osInfoParser.reader)

	for {
		line, err := lineReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			return errors.Wrapf(err, "Error parsing os information from file %q", osReleaseFile)
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		split := strings.Split(line, "=")
		if len(split) != 2 {
			log.Warnf("%q is not a valid line in file %q", line, osReleaseFile)
			continue
		}

		if split[0] == "NAME" {
			hostInfo.OSName = strings.ReplaceAll(split[1], "\"", "")

			// /etc/os-release contains NAME="Red Hat Enterprise Linux" whereas 'lsbrelease' returned
			// 'RedHatEnterprise'.  Strip out the spaces and adjust the name for backward compatablity
			// with older flavors.
			if hostInfo.OSName == "Red Hat Enterprise Linux" {
				hostInfo.OSName = "RedHatEnterprise"
			}

		} else if split[0] == "VERSION_ID" {
			hostInfo.OSVersion = strings.ReplaceAll(split[1], "\"", "")
		}
	}

	return nil
}
