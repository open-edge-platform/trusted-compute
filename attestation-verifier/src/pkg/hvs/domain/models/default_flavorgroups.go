/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package models

type FlavorGroups string

const (
	FlavorGroupsAutomatic        FlavorGroups = "automatic"
	FlavorGroupsHostUnique       FlavorGroups = "host_unique"
	FlavorGroupsPlatformSoftware FlavorGroups = "platform_software"
	FlavorGroupsWorkloadSoftware FlavorGroups = "workload_software"
)

func (dfg FlavorGroups) String() string {
	return string(dfg)
}

func GetDefaultFlavorGroups() map[FlavorGroups]bool {
	return map[FlavorGroups]bool{FlavorGroupsAutomatic: true, FlavorGroupsHostUnique: true, FlavorGroupsPlatformSoftware: true, FlavorGroupsWorkloadSoftware: true}
}

func IsDefaultFlavorgroup(flavorGroupName string) bool {
	_, isDefaultFlavorgroup := GetDefaultFlavorGroups()[FlavorGroups(flavorGroupName)]
	return isDefaultFlavorgroup
}
