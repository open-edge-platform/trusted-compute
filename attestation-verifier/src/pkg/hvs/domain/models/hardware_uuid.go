/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"database/sql/driver"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// HwUUID can be used with the standard sql package to represent a
// UUID value that can be NULL in the database
type HwUUID struct {
	UUID  uuid.UUID
	Valid bool
}

// Interface implements the nullable interface. It returns nil if
// the HwUUID is not valid, otherwise it returns the UUID value.
func (u HwUUID) Interface() interface{} {
	if !u.Valid {
		return nil
	}
	return u.UUID
}

// NewHwUUID returns a new, properly instantiated
// HwUUID object.
func NewHwUUID(u uuid.UUID) HwUUID {
	return HwUUID{UUID: u, Valid: true}
}

// Value implements the driver.Valuer interface.
func (u HwUUID) Value() (driver.Value, error) {
	if !u.Valid {
		return nil, nil
	}
	// Delegate to UUID Value function
	return u.UUID.Value()
}

// Scan implements the sql.Scanner interface.
func (u *HwUUID) Scan(src interface{}) error {
	if src == nil {
		u.UUID, u.Valid = uuid.Nil, false
		return nil
	}

	// Delegate to UUID Scan function
	u.Valid = true
	return u.UUID.Scan(src)
}

// MarshalJSON marshals the underlying value to a
// proper JSON representation.
func (u HwUUID) MarshalJSON() ([]byte, error) {
	if u.Valid {
		return json.Marshal(u.UUID.String())
	}
	return json.Marshal(nil)
}

// UnmarshalJSON will unmarshal a JSON value into
// the proper representation of that value.
func (u *HwUUID) UnmarshalJSON(text []byte) error {
	u.Valid = false
	u.UUID = uuid.Nil
	if string(text) == "null" {
		return nil
	}

	s := string(text)
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")

	us, err := uuid.Parse(s)
	if err != nil {
		return err
	}

	u.UUID = us
	u.Valid = true
	return nil
}
