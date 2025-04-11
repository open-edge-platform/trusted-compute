/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package privacyca

import (
	"crypto"
	"crypto/rsa"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

var log = commLog.GetDefaultLogger()

// PrivacyCa is interface for processing the identity request from the trust agent.
type PrivacyCa interface {
	ProcessIdentityRequest(model.IdentityRequest, crypto.PublicKey, []byte) (model.IdentityProofRequest, error)
	GetEkCert(model.IdentityChallengePayload, crypto.PrivateKey) ([]byte, error)
	GetIdentityChallengeRequest([]byte, *rsa.PublicKey, model.IdentityRequest) (model.IdentityChallengePayload, error)
}
