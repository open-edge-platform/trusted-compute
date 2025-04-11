/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"time"
)

// TagCertificate model lays out the attributes required for TagCertificates
type TagCertificate struct {
	// swagger:strfmt uuid
	ID uuid.UUID `json:"id"`
	// swagger:strfmt base64
	Certificate []byte    `json:"certificate"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// swagger:strfmt uuid
	HardwareUUID  uuid.UUID `json:"hardware_uuid"`
	TagCertDigest string    `json:"asset_tag_digest"`
}

// TagCertificateCollection is the response sent by the tag-certificate API
type TagCertificateCollection struct {
	TagCertificates []*TagCertificate `json:"certificates" xml:"certificates"`
}

// SetAssetTagDigest computes the hash of the Asset Tag certificate
func (tc *TagCertificate) SetAssetTagDigest() {
	// get Tag Cert hash
	tcHash, _ := crypt.GetHashData(tc.Certificate, crypto.SHA384)
	tc.TagCertDigest = base64.StdEncoding.EncodeToString(tcHash)
}
