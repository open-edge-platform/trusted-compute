/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/google/uuid"
)

//ResourceProviders Resources for Openstack
type ResourceProviders struct {
	Generation int       `json:"generation"`
	HostID     uuid.UUID `json:"uuid"`
	Links      []Links   `json:"links"`
	Name       string    `json:"name"`
}

//OpenstackResources Resources for Openstack
type OpenstackResources struct {
	ResourceProviders []ResourceProviders `json:"resource_providers"`
}

//Links Resources for Openstack
type Links struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

//OpenStackTrait OpenStack Traits for resource
type OpenStackTrait struct {
	Traits                     []string `json:"traits"`
	ResourceProviderGeneration int      `json:"resource_provider_generation"`
}
