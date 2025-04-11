/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"time"
)

// TagCertificateFilterCriteria is passed to the TagCertificates Search API to filter the response
type TagCertificateFilterCriteria struct {
	// swagger:strfmt uuid
	ID              uuid.UUID `json:"id"`
	SubjectEqualTo  string    `json:"subjectEqualTo"`
	SubjectContains string    `json:"subjectContains"`
	IssuerEqualTo   string    `json:"issuerEqualTo"`
	IssuerContains  string    `json:"issuerContains"`
	ValidOn         time.Time `json:"validOn"`
	ValidBefore     time.Time `json:"validBefore"`
	ValidAfter      time.Time `json:"validAfter"`
	// swagger:strfmt uuid
	HardwareUUID uuid.UUID `json:"hardwareUuid"`
}

// TagCertificateCreateCriteria holds the data used to create a TagCertificate
type TagCertificateCreateCriteria struct {
	// HardwareUUID The hardware UUID of the host to which the tag certificate is associated.
	// swagger:strfmt uuid
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
	// SelectionContent is an array of one or more key-value pairs with the tag selection attributes.
	SelectionContent []hvs.TagKvAttribute `json:"selection_content,omitempty"`
}

// TagCertificateDeployCriteria holds the data used to deploy a TagCertificate onto a host
type TagCertificateDeployCriteria struct {
	// swagger:strfmt uuid
	CertID uuid.UUID `json:"certificate_id,omitempty"`
}
