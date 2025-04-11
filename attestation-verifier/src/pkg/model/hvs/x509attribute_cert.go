/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

const (
	authorityKeyIdOid = "2.5.29.35"
)

// X509AttributeCertificate holds a subset of x509.Certificate that has relevant information for Flavor
type X509AttributeCertificate struct {
	Encoded           []byte      `json:"encoded"`
	Issuer            string      `json:"issuer"`
	SerialNumber      int64       `json:"serial_number"`
	Subject           string      `json:"subject"`
	NotBefore         time.Time   `json:"not_before"`
	NotAfter          time.Time   `json:"not_after"`
	Attributes        []Attribute `json:"attribute,omitempty"`
	FingerprintSha384 string      `json:"fingerprint_sha384"`
}

// Attribute is used to store the custom Asset Tags embedded in the tag certificate
type Attribute struct {
	AttrType struct {
		ID string `json:"id"`
	} `json:"attr_type"`
	AttributeValues []AttrObjects `json:"attribute_values,omitempty"`
}

// AttrObject holds the individual TagKeyValue Pair - TagKVAttribute which is decoded from ASN.1 values
type AttrObjects struct {
	KVPair TagKvAttribute `json:"objects"`
}

// String returns the base64 encoded string of encoded field
func (c X509AttributeCertificate) String() string {
	return base64.StdEncoding.EncodeToString(c.Encoded)
}

// NewX509AttributeCertificate returns an instance of the X509AttributeCertificate taking a generic x509.Certificate as input
func NewX509AttributeCertificate(tagCert *x509.Certificate) (*X509AttributeCertificate, error) {
	var xAttrCert X509AttributeCertificate
	var attrkvas []Attribute

	// check for the custom ASN1 tags in Extra Extensions and pack into the Attributes
	for _, attrExt := range tagCert.Extensions {
		var tagkva1 TagKvAttribute
		var attrObjects []AttrObjects
		var attrkva Attribute

		// fill in the ID
		attrkva.AttrType.ID = attrExt.Id.String()

		// check if the attribute tags can be unmarshalled
		// but skip if this is an AuthorityKeyID - OID 2.5.29.35 as the unmarshal will fail
		// this change affects all versions of go >=1.15 caused by:
		//
		if attrkva.AttrType.ID == authorityKeyIdOid {
			continue
		}

		_, err := asn1.Unmarshal(attrExt.Value, &tagkva1)
		if err != nil {
			return nil, errors.Wrap(err, "Failure unmarshalling ASN1 Attributes")
		}

		// Append to list of Elements
		attrObjects = append(attrObjects, AttrObjects{
			KVPair: tagkva1,
		})

		attrkva.AttributeValues = attrObjects
		attrkvas = append(attrkvas, attrkva)
	}

	// get cert hash
	certHash, err := crypt.GetCertHashInHex(tagCert, crypto.SHA384)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get tag certificate SHA384 hash")
	}

	// Assemble certificate
	xAttrCert = X509AttributeCertificate{
		Encoded:           tagCert.Raw,
		Issuer:            tagCert.Issuer.String(),
		SerialNumber:      tagCert.SerialNumber.Int64(),
		Subject:           tagCert.Subject.CommonName,
		NotBefore:         tagCert.NotBefore,
		NotAfter:          tagCert.NotAfter,
		Attributes:        attrkvas,
		FingerprintSha384: certHash,
	}

	return &xAttrCert, nil
}
