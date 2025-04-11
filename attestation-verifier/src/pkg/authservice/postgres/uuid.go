/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// UUID returns a random uuid string and error if there is any
func UUID() (string, error) {

	uuid, err := uuid.NewRandom()
	if err == nil {
		return uuid.String(), nil
	} else {
		return "", errors.Wrap(err, "failed to generate UUID")
	}
}
