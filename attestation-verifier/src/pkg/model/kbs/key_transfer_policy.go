/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aps"
)

// KeyTransferPolicy - used in key transfer policy create request and response.
type KeyTransferPolicy struct {
	// swagger:strfmt uuid
	ID              uuid.UUID             `json:"id,omitempty"`
	CreatedAt       time.Time             `json:"created_at,omitempty"`
	UpdatedAt       time.Time             `json:"updated_at,omitempty"`
	AttestationType []aps.AttestationType `json:"attestation_type"`
	TDX             *TdxPolicy            `json:"tdx,omitempty"`
	SGX             *SgxPolicy            `json:"sgx,omitempty"`
	IssuerName      []string              `json:"cert_issuer,omitempty"`
}

type TdxPolicy struct {
	Attributes *TdxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type TdxAttributes struct {
	MrSignerSeam       []string `json:"mrsignerseam,omitempty"`
	MrSeam             []string `json:"mrseam,omitempty"`
	SeamSvn            *uint8   `json:"seamsvn,omitempty"`
	MRTD               []string `json:"mrtd,omitempty"`
	RTMR0              string   `json:"rtmr0,omitempty"`
	RTMR1              string   `json:"rtmr1,omitempty"`
	RTMR2              string   `json:"rtmr2,omitempty"`
	RTMR3              string   `json:"rtmr3,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type SgxPolicy struct {
	Attributes *SgxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type SgxAttributes struct {
	MrSigner           []string `json:"mrsigner,omitempty"`
	IsvProductId       []uint16 `json:"isvprodid,omitempty"`
	MrEnclave          []string `json:"mrenclave,omitempty"`
	IsvSvn             *uint16  `json:"isvsvn,omitempty"`
	ClientPermissions  []string `json:"client_permissions,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type KeyTransferPolicyAttributes struct {
	// swagger:strfmt uuid
	ID                                uuid.UUID `json:"id,omitempty"`
	CreatedAt                         time.Time `json:"created_at,omitempty"`
	SGXEnclaveIssuerAnyof             []string  `json:"sgx_enclave_issuer_anyof"`
	SGXEnclaveIssuerProductID         *uint16   `json:"sgx_enclave_issuer_product_id"`
	SGXEnclaveMeasurementAnyof        []string  `json:"sgx_enclave_measurement_anyof,omitempty"`
	SGXEnclaveSVNMinimum              uint16    `json:"sgx_enclave_svn_minimum,omitempty"`
	TLSClientCertificateIssuerCNAnyof []string  `json:"tls_client_certificate_issuer_cn_anyof,omitempty"`
	TLSClientCertificateSANAnyof      []string  `json:"client_permissions_anyof,omitempty"`
	TLSClientCertificateSANAllof      []string  `json:"client_permissions_allof,omitempty"`
	AttestationTypeAnyof              []string  `json:"attestation_type_anyof,omitempty"`
	SGXEnforceTCBUptoDate             bool      `json:"sgx_enforce_tcb_up_to_date,omitempty"`
}
