/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

/**
 *
 * @author mullas
 */

// BootGuardProfile
type BootGuardProfile struct {
	Name  string
	Value string
}

func BootGuardProfile4() BootGuardProfile {
	return BootGuardProfile{
		Name:  "BTGP4",
		Value: "51",
	}
}

func BootGuardProfile5() BootGuardProfile {
	return BootGuardProfile{
		Name:  "BTGP5",
		Value: "7D",
	}
}
