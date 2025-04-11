/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wls"
)

/**
 *
 * @author arijitgh
 */

// SignedImageFlavor struct defines the image flavor and
// its corresponding signature
type SignedImageFlavor struct {
	ImageFlavor wls.Image `json:"flavor"`
	Signature   string    `json:"signature"`
}

type SignedFlavorCollection struct {
	Flavors []wls.SignedImageFlavor `json:"signed_flavors"`
}
