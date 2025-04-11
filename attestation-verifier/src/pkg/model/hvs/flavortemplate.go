/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/google/uuid"
)

//PCR - To store PCR index with respective PCR bank.
type PCR struct {
	// Valid PCR index is from 0 to 23.
	Index int `json:"index"`
	// Valid PCR banks are SHA1, SHA256, SHA384 and SHA512.
	Bank []string `json:"bank"`
}

// EventlogEquals key needs to be included when equals rule has to be applied for the particular PCR. Sample value: "eventlog_equals": {"excluding_tags": ["LCP_CONTROL_HASH","initrd","vmlinuz"]}
type EventLogEquals struct {
	// To exclude events, list of event tags need to be provided as string array.
	ExcludingTags []string `json:"excluding_tags,omitempty"`
}

type PcrRules struct {
	Pcr PCR `json:"pcr"`
	// Boolean value to denote whether pcr matches rule needs to be applied.
	PcrMatches     *bool           `json:"pcr_matches,omitempty"`
	EventlogEquals *EventLogEquals `json:"eventlog_equals,omitempty"`
	// To include events, list of event tags need to be provided as string array. Sample value: "eventlog_includes": ["shim","db","kek","vmlinuz"]
	EventlogIncludes []string `json:"eventlog_includes,omitempty"`
}

type FlavorPart struct {
	// Meta is key:value pair section used to define flavorparts with its own meta fields.
	Meta     map[string]interface{} `json:"meta,omitempty"`
	PcrRules []PcrRules             `json:"pcr_rules"`
}

// swagger:parameters FlavorParts
type FlavorParts struct {
	Platform   *FlavorPart `json:"PLATFORM,omitempty"`
	OS         *FlavorPart `json:"OS,omitempty"`
	HostUnique *FlavorPart `json:"HOST_UNIQUE,omitempty"`
	Ima        *FlavorPart `json:"IMA,omitempty"`
}

type FlavorTemplateReq struct {
	FlavorgroupNames []string       `json:"flavorgroup_names,omitempty"`
	FlavorTemplate   FlavorTemplate `json:"flavor_template"`
}

type FlavorTemplate struct {
	// swagger: strfmt uuid
	ID    uuid.UUID `json:"id" gorm:"primary_key;type:uuid"`
	Label string    `json:"label"`
	// An array of 'jsonquery' statements that are used to determine if the template should be executed. Sample value: ["//host_info/os_name//*[text()='RedHatEnterprise']","//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']"].
	Condition   []string     `json:"condition" sql:"type:text[]"`
	FlavorParts *FlavorParts `json:"flavor_parts,omitempty" sql:"type:JSONB"`
}

type FlavorTemplateFlavorgroupCollection struct {
	FlavorTemplateFlavorgroups []FlavorTemplateFlavorgroup `json:"flavorgroup_flavortemplate_links" xml:"flavorgroup_flavortemplate_link"`
}

type FlavorTemplateFlavorgroup struct {
	// swagger:strfmt uuid
	FlavortemplateId uuid.UUID `json:"flavortemplate_id,omitempty"`
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}

type FlavorTemplateFlavorgroupCreateRequest struct {
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}

type PcrListRules struct {
	PcrBank     []string
	PcrMatches  bool
	PcrEquals   PcrEquals
	PcrIncludes map[string]bool
}

type PcrEquals struct {
	IsPcrEquals   bool
	ExcludingTags map[string]bool
}
