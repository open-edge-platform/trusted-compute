/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package instance

/**
 *
 * @author purvades
 *
 */

type Manifest struct {
	InstanceInfo           Info `json:"instance_info"`
	ImageEncrypted         bool `json:"image_encrypted"`
	ImageIntegrityEnforced bool `json:"image_integrity_enforced,omitempty"`
}

type Info struct {
	InstanceID       string `json:"instance_id"`
	HostHardwareUUID string `json:"host_hardware_uuid"`
	ImageID          string `json:"image_id"`
}
