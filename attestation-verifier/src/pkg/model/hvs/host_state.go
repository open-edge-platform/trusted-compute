/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"bytes"
	"encoding/json"
	"strings"
)

// HostState is an enumerated set of states that describe the connection state between VS and the Host at any point of time
type HostState int

const (
	HostStateInvalid HostState = iota
	HostStateUnknown
	HostStateConnected
	HostStateQueue
	HostStateConnectionFailure
	HostStateConnectionTimeout
	HostStateUnauthorized
	HostStateAIKNotProvisioned
	HostStateEndorsementCertificateNotPresent
	HostStateMeasurementLaunchFailure
	HostStateTPMOwnershipFailure
	HostStateTPMNotPresent
	HostStateTPMNotSupported
)

var hostStatusToString = [...]string{
	HostStateInvalid:                          "INVALID",
	HostStateUnknown:                          "UNKNOWN",
	HostStateConnected:                        "CONNECTED",
	HostStateQueue:                            "QUEUE",
	HostStateConnectionFailure:                "CONNECTION_FAILURE",
	HostStateConnectionTimeout:                "CONNECTION_TIMEOUT",
	HostStateUnauthorized:                     "UNAUTHORIZED",
	HostStateAIKNotProvisioned:                "AIK_NOT_PROVISIONED",
	HostStateEndorsementCertificateNotPresent: "EC_NOT_PRESENT",
	HostStateMeasurementLaunchFailure:         "MEASURED_LAUNCH_FAILURE",
	HostStateTPMOwnershipFailure:              "TPM_OWNERSHIP_FAILURE",
	HostStateTPMNotPresent:                    "TPM_NOT_PRESENT",
	HostStateTPMNotSupported:                  "UNSUPPORTED_TPM",
}

var hostStatusToID = map[string]HostState{
	"INVALID":                 HostStateInvalid,
	"UNKNOWN":                 HostStateUnknown,
	"CONNECTED":               HostStateConnected,
	"QUEUE":                   HostStateQueue,
	"CONNECTION_FAILURE":      HostStateConnectionFailure,
	"CONNECTION_TIMEOUT":      HostStateConnectionTimeout,
	"UNAUTHORIZED":            HostStateUnauthorized,
	"AIK_NOT_PROVISIONED":     HostStateAIKNotProvisioned,
	"EC_NOT_PRESENT":          HostStateEndorsementCertificateNotPresent,
	"MEASURED_LAUNCH_FAILURE": HostStateMeasurementLaunchFailure,
	"TPM_OWNERSHIP_FAILURE":   HostStateTPMOwnershipFailure,
	"TPM_NOT_PRESENT":         HostStateTPMNotPresent,
	"UNSUPPORTED_TPM":         HostStateTPMNotSupported,
}

// GetHostState is used to convert the HostState from plain string format to a HostState
// It falls back to setting the HostState to INVALID if all else fails
func GetHostState(str string) HostState {
	if s, ok := hostStatusToID[strings.ToUpper(str)]; ok {
		return s
	}
	return HostStateInvalid
}

// String is used to convert the HostState from enum value to plain string format
func (s HostState) String() string {
	return hostStatusToString[s]
}

// Valid performs boundary-checks on the value of HostState
func (s HostState) Valid() bool {
	return s >= HostStateInvalid && s <= HostStateTPMNotSupported
}

// MarshalJSON marshals the enum as a quoted json string
func (s HostState) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(hostStatusToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals a quoted json string to the enum value
func (s *HostState) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Unknown' in this case.
	*s = hostStatusToID[j]
	return nil
}
