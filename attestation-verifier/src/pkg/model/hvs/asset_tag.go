/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// TagCertConfig is the input struct for Asset-Tag create interface implementation
type TagCertConfig struct {
	SubjectUUID       string
	PrivateKey        interface{}
	TagCACert         *x509.Certificate
	TagAttributes     []TagKvAttribute
	ValidityInSeconds int
}

// TagCertBuilderConfig struct is used to create an asset-tag certificate for a host with key-value attributes
type TagCertBuilderConfig struct {
	TagCertConfig    TagCertConfig
	SerialNumber     *big.Int
	ValidityDuration time.Duration
	SubjectName      pkix.Name
	Extensions       []pkix.Extension
}

// TagKvAttribute struct is the key-value asset-tag attributes
type TagKvAttribute struct {
	Key   string `json:"name"`
	Value string `json:"value"`
}
