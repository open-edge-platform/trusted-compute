/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/sha512"
	"encoding/json"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"

	"github.com/google/uuid"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

// Flavor sourced from the lib/flavor - this is a external request/response on the HVS API
// Flavor is a standardized set of expectations that determines what platform
// measurements will be considered “trusted.”
type Flavor struct {
	// Meta section is mandatory for all Flavor types
	Meta Meta  `json:"meta"`
	Bios *Bios `json:"bios,omitempty"`
	// Hardware section is unique to Platform Flavor type
	Hardware *Hardware    `json:"hardware,omitempty"`
	Pcrs     []FlavorPcrs `json:"pcrs,omitempty"`
	// External section is unique to AssetTag Flavor type
	External *External `json:"external,omitempty"`
	Software *Software `json:"software,omitempty"`
	ImaLogs  *Ima      `json:"ima_logs,omitempty"`
}

// NewFlavor returns a new instance of Flavor
func NewFlavor(meta *Meta, bios *Bios, hardware *Hardware, pcrs []FlavorPcrs, external *External, software *Software, imaLogs *Ima) *Flavor {
	// Since maps are hard to marshal as JSON, let's try to convert the DigestAlgorithm and PcrIndex to strings
	return &Flavor{
		Meta:     *meta,
		Bios:     bios,
		Hardware: hardware,
		Pcrs:     pcrs,
		External: external,
		Software: software,
		ImaLogs:  imaLogs,
	}
}

// GetFlavorDigest Calculates the SHA384 hash of the Flavor's json data for use when
// signing/verifying signed flavors.
func (flavor *Flavor) getFlavorDigest() ([]byte, error) {
	// account for a differences in properties set at runtime
	tempFlavor := *flavor
	tempFlavor.Meta.ID = uuid.Nil

	flavorJSON, err := json.Marshal(tempFlavor)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred attempting to convert the flavor to json")
	}

	if flavorJSON == nil || len(flavorJSON) == 0 {
		return nil, errors.New("The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	_, err = hashEntity.Write(flavorJSON)
	if err != nil {
		return nil, errors.Wrap(err, "Error writing flavor hash")
	}
	return hashEntity.Sum(nil), nil
}

// FlavorCollection is a list of Flavor objects in response to a Flavor Search query
type FlavorCollection struct {
	Flavors []Flavors `json:"flavors"`
}

type Flavors struct {
	Flavor Flavor `json:"flavor"`
}

// SignedFlavorCollection is a list of SignedFlavor objects
type SignedFlavorCollection struct {
	SignedFlavors []SignedFlavor `json:"signed_flavors"`
	Next          string         `json:"next,omitempty"`
	Previous      string         `json:"prev,omitempty"`
}

func (s SignedFlavorCollection) GetFlavors(flavorPart string) []SignedFlavor {
	signedFlavors := []SignedFlavor{}
	for _, flavor := range s.SignedFlavors {
		if flavor.Flavor.Meta.Description[FlavorPartDescription] == flavorPart {
			signedFlavors = append(signedFlavors, flavor)
		}
	}
	return signedFlavors
}

type FlavorCreateRequest struct {
	ConnectionString       string                 `json:"connection_string,omitempty"`
	FlavorCollection       FlavorCollection       `json:"flavor_collection,omitempty"`
	SignedFlavorCollection SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
	FlavorgroupNames       []string               `json:"flavorgroup_names,omitempty"`
	FlavorParts            []FlavorPartName       `json:"partial_flavor_types,omitempty"`
}

// Bios holds details of the Bios vendor firmware information
type Bios struct {
	BiosName    string `json:"bios_name"`
	BiosVersion string `json:"bios_version"`
}

// Encryption contains information pertaining to the encryption policy of the image
type Encryption struct {
	KeyURL string `json:"key_url,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// External is a component of flavor that encloses the AssetTag cert
type External struct {
	AssetTag AssetTag `json:"asset_tag,omitempty"`
}

// AssetTag is used to hold the Asset Tag certificate provisioned by VS for the host
type AssetTag struct {
	TagCertificate X509AttributeCertificate `json:"tag_certificate"`
}

type Hardware struct {
	Vendor         string   `json:"vendor,omitempty"`
	ProcessorInfo  string   `json:"processor_info,omitempty"`
	ProcessorFlags string   `json:"processor_flags,omitempty"`
	Feature        *Feature `json:"feature,omitempty"`
}

// Meta holds metadata information related to the Flavor
type Meta struct {
	Schema *Schema `json:"schema,omitempty"`
	// swagger:strfmt uuid
	ID          uuid.UUID              `json:"id"`
	Realm       string                 `json:"realm,omitempty"`
	Description map[string]interface{} `json:"description,omitempty"`
	Vendor      constants.Vendor       `json:"vendor,omitempty"` // KWT
}

// Schema defines the Uri of the schema
type Schema struct {
	Uri string `json:"uri,omitempty"`
}

// Software consists of integrity measurements of Software/OS related resources
type Software struct {
	Measurements   map[string]model.FlavorMeasurement `json:"measurements,omitempty"`
	CumulativeHash string                             `json:"cumulative_hash,omitempty"`
}

type Ima struct {
	Measurements  []Measurements `json:"ima_measurements,omitempty"`
	ImaTemplate   string         `json:"ima_template,omitempty"`
	ExpectedValue string         `json:"expected_value,omitempty"`
}
