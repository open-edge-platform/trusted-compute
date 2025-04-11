/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package asset_tag

import (
	hc "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

// AssetTag interface is used to create and deploy an asset tag certificate on a host
type AssetTag interface {
	CreateAssetTag(hvs.TagCertConfig) ([]byte, error)
	DeployAssetTag(hc.HostConnector, string, string) error
}

// NewAssetTag returns an instance to the AssetTag interface
func NewAssetTag() AssetTag {
	return &atag{}
}
