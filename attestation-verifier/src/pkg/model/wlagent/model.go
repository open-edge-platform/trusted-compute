/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

type RegisterKeyInfo struct {
	PublicKeyModulus       []byte `json:"public_key_modulus,omitempty"`
	TpmCertifyKey          []byte `json:"tpm_certify_key,omitempty"`
	TpmCertifyKeySignature []byte `json:"tpm_certify_key_signature,omitempty"`
	AikDerCertificate      []byte `json:"aik_der_certificate,omitempty"`
	NameDigest             []byte `json:"name_digest,omitempty"`
	TpmVersion             string `json:"tpm_version,omitempty"`
	OsType                 string `json:"operating_system,omitempty"`
}

type BindingKeyCert struct {
	BindingKeyCertificate []byte `json:"binding_key_der_certificate,omitempty"`
}

type SigningKeyCert struct {
	SigningKeyCertificate []byte `json:"signing_key_der_certificate,omitempty"`
}
