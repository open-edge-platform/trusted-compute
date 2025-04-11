/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	commonLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

var log = commonLog.GetDefaultLogger()

// HostInfoParser collects the host's meta-data from the current
// host and returns a "HostInfo" struct (see intel-secl/v5/pkg/model/ta/HostInfo structure).
type HostInfoParser interface {
	// This function will always return a HostInfo structure that may be partially populated
	// if errors occur.  Any errors that occur while HostInfo data is being collected will
	// be logged (not thrown).
	Parse() *model.HostInfo
}

// InfoParser is an interface implmented internally to collect
// the different fields of the HostInfo structure.
type InfoParser interface {
	// Init is called on each of the 'infoParsers' during NewHostInfoProcess.
	// Since parsers are registered statically, it provides the parser an
	// opportunity to initialize itself before 'Parse' is called.  Primarily,
	// this allows unit tests to configure the parser with mocked dependencies,
	// whereas the 'Init' is used to create real dependencies at runtime.
	// InfoParses should only return an error under 'panic' type conditions so
	// that a client call to 'HostInfoParser.Parse()' always returns a
	// 'HostInfo' structure (even if partially populated).
	Init() error

	// Parse is called on each of the 'infoParsers' during HostInfoParser.Parse().
	// The InfoParse should populate the 'HostInfo' parameter with data and should
	// avoid returning errors so that 'HostInfo' is successfully populated (even
	// with empty data) during the call to HostInfoParser.Parse().
	Parse(*model.HostInfo) error
}

// NewHostInfoParser creates a new HostInfoParser with a collection of 'InfoParsers'.
func NewHostInfoParser() HostInfoParser {
	return &hostInfoParserImpl{
		parsers: []InfoParser{
			&smbiosInfoParser{},
			&osInfoParser{},
			&msrInfoParser{},
			&tpmInfoParser{},
			&shellInfoParser{},
			&fileInfoParser{},
			&miscInfoParser{},
			&secureBootParser{},
		},
	}
}

//-------------------------------------------------------------------------------------------------
// HostInfoParser implementation
//-------------------------------------------------------------------------------------------------
type hostInfoParserImpl struct {
	parsers []InfoParser
}

// Implements HostInfoParser.Parse()
func (hostInfoParser *hostInfoParserImpl) Parse() *model.HostInfo {

	hostInfo := model.HostInfo{}

	for _, parser := range hostInfoParser.parsers {

		// intialize the parser's dependencies (if any)
		err := parser.Init()

		// if an error occurs, just log an error message and do not call 'Parse()'.
		if err != nil {
			log.Errorf("Failed to intialize parser %T, it will not be run: %+v", parser, err)
			continue
		}

		// Attempt to parse all information from each of the "infoParsers".  If an
		// error occurs, just log a message so that (in the worst case scenario) the
		// HostInfo data structure is empty with defaults (but still created).
		err = parser.Parse(&hostInfo)
		if err != nil {
			log.Errorf("An error occurred in info parser '%T': %+v", parser, err)
		}
	}

	return &hostInfo
}
