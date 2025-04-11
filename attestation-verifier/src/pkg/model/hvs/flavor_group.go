/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"encoding/json"

	"github.com/google/uuid"
)

type FlavorgroupCollection struct {
	Flavorgroups []FlavorGroup `json:"flavorgroups" xml:"flavorgroup"`
	Next         string        `json:"next,omitempty" xml:"next"`
	Previous     string        `json:"prev,omitempty" xml:"prev"`
}

type FlavorMatchPolicies []FlavorMatchPolicy

type FlavorMatchPolicyCollection struct {
	FlavorMatchPolicies `json:"flavor_match_policies,omitempty"`
}

type FlavorGroup struct {
	// swagger:strfmt uuid
	RowId int       `json:"-"`
	ID    uuid.UUID `json:"id,omitempty"`
	Name  string    `json:"name,omitempty"`
	// swagger:strfmt uuid
	FlavorIds []uuid.UUID `json:"flavorIds,omitempty"`
	// swagger:strfmt uuid
	FlavorTemplateIds []uuid.UUID         `json:"flavorTemplateIds,omitempty"`
	Flavors           []Flavor            `json:"flavors,omitempty"`
	MatchPolicies     FlavorMatchPolicies `json:"flavor_match_policies,omitempty"`
}

type FlavorMatchPolicy struct {
	FlavorPart  FlavorPartName `json:"flavor_part,omitempty"`
	MatchPolicy MatchPolicy    `json:"match_policy,omitempty"`
}

type MatchPolicy struct {
	MatchType MatchType            `json:"match_type,omitempty"`
	Required  FlavorRequiredPolicy `json:"required,omitempty"`
}

type MatchType string

const (
	MatchTypeAnyOf  MatchType = "ANY_OF"
	MatchTypeAllOf  MatchType = "ALL_OF"
	MatchTypeLatest MatchType = "LATEST"
)

func (mt MatchType) String() string {
	return string(mt)
}

type FlavorRequiredPolicy string

const (
	FlavorRequired          FlavorRequiredPolicy = "REQUIRED"
	FlavorRequiredIfDefined FlavorRequiredPolicy = "REQUIRED_IF_DEFINED"
)

func (req FlavorRequiredPolicy) String() string {
	return string(req)
}

func NewFlavorMatchPolicy(fp FlavorPartName, mp MatchPolicy) FlavorMatchPolicy {
	return FlavorMatchPolicy{
		FlavorPart:  fp,
		MatchPolicy: mp,
	}
}

func NewMatchPolicy(mt MatchType, rp FlavorRequiredPolicy) MatchPolicy {
	return MatchPolicy{
		MatchType: mt,
		Required:  rp,
	}
}

func (r FlavorGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                          uuid.UUID                   `json:"id,omitempty"`
		Name                        string                      `json:"name,omitempty"`
		FlavorIds                   []uuid.UUID                 `json:"flavorIds,omitempty"`
		Flavors                     []Flavor                    `json:"flavors,omitempty"`
		FlavorTemplateIds           []uuid.UUID                 `json:"flavorTemplateIds,omitempty"`
		FlavorMatchPolicyCollection FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
	}{
		ID:                          r.ID,
		Name:                        r.Name,
		FlavorIds:                   r.FlavorIds,
		Flavors:                     r.Flavors,
		FlavorTemplateIds:           r.FlavorTemplateIds,
		FlavorMatchPolicyCollection: FlavorMatchPolicyCollection{r.MatchPolicies},
	})
}

func (r *FlavorGroup) UnmarshalJSON(b []byte) error {
	decoded := new(struct {
		ID                          uuid.UUID                   `json:"id,omitempty"`
		Name                        string                      `json:"name,omitempty"`
		FlavorIds                   []uuid.UUID                 `json:"flavorIds,omitempty"`
		FlavorTemplateIds           []uuid.UUID                 `json:"flavorTemplateIds,omitempty"`
		Flavors                     []Flavor                    `json:"flavors,omitempty"`
		FlavorMatchPolicyCollection FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
	})
	err := json.Unmarshal(b, decoded)
	if err == nil {
		r.ID = decoded.ID
		r.Name = decoded.Name
		r.FlavorIds = decoded.FlavorIds
		r.FlavorTemplateIds = decoded.FlavorTemplateIds
		r.Flavors = decoded.Flavors
		r.MatchPolicies = decoded.FlavorMatchPolicyCollection.FlavorMatchPolicies
	}
	return err
}

// Function returns 3 maps. The reason for this is that we do not have to keep iterating over per part policy
// over and over again trying to look for information. Everything is gathered in one fell swoop
func (r *FlavorGroup) GetMatchPolicyMaps() (

	// Map to determine what is the match policy for each individual flavor part
	// eg : map["SOFTWARE"] = MatchPolicy{MatchType: "ANY_OF", Required: "Required_if_defined"}
	map[FlavorPartName]MatchPolicy,
	// A map for match type to all the flavor part that has the particular match type
	// eg : map["AL_OF"] = []{"SOFTWARE", "PLATFORM"}
	map[MatchType][]FlavorPartName,
	// A map for required/ required if defined policy to all the flavor part
	// eg : map["Required_if_defined"] = {Software}
	map[FlavorRequiredPolicy][]FlavorPartName) {

	fpMap := make(map[FlavorPartName]MatchPolicy)
	mtMap := make(map[MatchType][]FlavorPartName)
	plcyMap := make(map[FlavorRequiredPolicy][]FlavorPartName)

	for _, plcy := range r.MatchPolicies {
		fpMap[plcy.FlavorPart] = plcy.MatchPolicy

		mtMap[plcy.MatchPolicy.MatchType] = append(mtMap[plcy.MatchPolicy.MatchType], plcy.FlavorPart)
		plcyMap[plcy.MatchPolicy.Required] = append(plcyMap[plcy.MatchPolicy.Required], plcy.FlavorPart)
	}
	return fpMap, mtMap, plcyMap
}

type FlavorgroupFlavorLink struct {
	// swagger:strfmt uuid
	FlavorGroupID uuid.UUID `json:"flavorgroup_id"`
	// swagger:strfmt uuid
	FlavorID uuid.UUID `json:"flavor_id"`
}

type FlavorgroupFlavorLinkCollection struct {
	FGFLinks []FlavorgroupFlavorLink `json:"flavor_flavorgroup_links,omitempty"`
}

// FlavorgroupFlavorLinkCriteria is used to hold the request details of a Flavor-FlavorGroup Link Request
type FlavorgroupFlavorLinkCriteria struct {
	// swagger:strfmt uuid
	FlavorID uuid.UUID `json:"flavor_id"`
}
