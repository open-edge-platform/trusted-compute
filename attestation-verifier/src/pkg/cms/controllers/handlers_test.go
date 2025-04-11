/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"strings"
	"testing"
)

func TestPrivilegeError(t *testing.T) {
	priv := privilegeError{
		StatusCode: 400,
		Message:    "privilegeError",
	}
	err := priv.Error()
	if !strings.Contains(err, "privilegeError") {
		t.Errorf("Error getting privilege error")
	}
}

func TestResourceError(t *testing.T) {
	priv := resourceError{
		StatusCode: 400,
		Message:    "resourceError",
	}
	err := priv.Error()
	if !strings.Contains(err, "resourceError") {
		t.Errorf("Error getting resourceError")
	}
}
