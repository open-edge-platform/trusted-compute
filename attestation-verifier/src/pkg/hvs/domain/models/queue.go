/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type QueueFilterCriteria struct {
	Id          uuid.UUID
	Action      string
	ParamKey    string
	ParamValue  string
	ParamMap    map[string]string
	QueueStates []QueueState
	Limit       int
}

type QueueState int

const (
	QueueStateUnknown QueueState = iota
	QueueStateNew
	QueueStatePending
	QueueStateCompleted
	QueueStateReturned
	QueueStateTimeout
	QueueStateConnectionFailure
	QueueStateError
)

var qstatusToString = [...]string{
	QueueStateNew:               "New",
	QueueStatePending:           "Pending",
	QueueStateCompleted:         "Completed",
	QueueStateReturned:          "Returned",
	QueueStateTimeout:           "Timeout",
	QueueStateConnectionFailure: "ConnectionFailure",
	QueueStateError:             "Error",
}

var qstatusToID = map[string]QueueState{
	"New":               QueueStateNew,
	"Pending":           QueueStatePending,
	"Completed":         QueueStateCompleted,
	"Returned":          QueueStateReturned,
	"Timeout":           QueueStateTimeout,
	"ConnectionFailure": QueueStateConnectionFailure,
	"Error":             QueueStateError,
}

func (s *QueueState) Unmarshal(str string) {
	var ok bool
	if *s, ok = qstatusToID[str]; ok {
		return
	}
	*s = 0
}

func (s QueueState) Valid() bool {
	return s >= QueueStateNew && s <= QueueStateError
}

// MarshalJSON marshals the enum as a quoted json string
func (s QueueState) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(qstatusToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshalls a quoted json string to the enum value
func (s *QueueState) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	*s = qstatusToID[j]
	return nil
}

type Queue struct {
	Id      uuid.UUID              `json:"id,omitempty"`
	Action  string                 `json:"action"`
	Params  map[string]interface{} `json:"action_params"`
	Created time.Time              `json:"created,omitempty"`
	Updated time.Time              `json:"updated,omitempty"`
	State   QueueState             `json:"state"`
	Message string                 `json:"message,omitempty"`
}
