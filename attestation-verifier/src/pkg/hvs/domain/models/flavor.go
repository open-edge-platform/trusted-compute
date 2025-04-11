/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

type flavors []hvs.Flavor
type signedFlavors []hvs.SignedFlavor

type FlavorCreateRequest struct {
	ConnectionString       string                     `json:"connection_string,omitempty"`
	FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
	SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
	FlavorgroupNames       []string                   `json:"flavorgroup_names,omitempty"`
	FlavorParts            []hvs.FlavorPartName       `json:"partial_flavor_types,omitempty"`
}

type FlavorFilterCriteria struct {
	Ids           []uuid.UUID
	Key           string
	Value         string
	FlavorgroupID uuid.UUID
	FlavorParts   []hvs.FlavorPartName
	Limit         int
	AfterId       int
}

type FlavorVerificationFC struct {
	FlavorFC              FlavorFilterCriteria
	FlavorMeta            map[hvs.FlavorPartName][]FlavorMetaKv
	FlavorPartsWithLatest map[hvs.FlavorPartName]bool
}

type FlavorMetaKv struct {
	Key   string
	Value interface{}
}

func (fcr FlavorCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ConnectionString       string                     `json:"connection_string,omitempty"`
		FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
		SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
		FlavorgroupNames       []string                   `json:"flavorgroup_names,omitempty"`
		FlavorParts            []hvs.FlavorPartName       `json:"partial_flavor_types,omitempty"`
	}{
		ConnectionString:       fcr.ConnectionString,
		FlavorCollection:       fcr.FlavorCollection,
		SignedFlavorCollection: fcr.SignedFlavorCollection,
		FlavorgroupNames:       fcr.FlavorgroupNames,
		FlavorParts:            fcr.FlavorParts,
	})
}

func (fcr *FlavorCreateRequest) UnmarshalJSON(b []byte) error {
	//Validate the FlavorCreateRequest keys as here it is overridden with custom UnmarshalJSON decoder.DisallowUnknownFields doesnt work
	validKeys := map[string]bool{"connection_string": true, "flavor_collection": true, "signed_flavor_collection": true, "flavorgroup_names": true, "partial_flavor_types": true}
	fcrKeysMap := map[string]interface{}{}
	if err := json.Unmarshal(b, &fcrKeysMap); err != nil {
		return err
	}
	for k := range fcrKeysMap {
		if _, ok := validKeys[k]; !ok {
			return errors.Errorf("Unknown key %s", k)
		}
	}

	decoded := new(struct {
		ConnectionString       string                     `json:"connection_string,omitempty"`
		FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
		SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
		FlavorgroupNames       []string                   `json:"flavorgroup_names,omitempty"`
		FlavorParts            []hvs.FlavorPartName       `json:"partial_flavor_types,omitempty"`
	})
	err := json.Unmarshal(b, &decoded)
	if err == nil {
		fcr.ConnectionString = decoded.ConnectionString
		fcr.FlavorgroupNames = decoded.FlavorgroupNames
		fcr.FlavorCollection = decoded.FlavorCollection
		fcr.SignedFlavorCollection = decoded.SignedFlavorCollection
		fcr.FlavorParts = decoded.FlavorParts
	}
	return err
}
