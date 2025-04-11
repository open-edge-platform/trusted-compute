/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wls

// Integrity contains information pertaining to the Integrity policy of the image
type Integrity struct {
	NotaryURL string `json:"notary_url,omitempty"`
}

// Encryption contains information pertaining to the encryption policy of the image
type Encryption struct {
	KeyURL string `json:"key_url,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// Image struct defines the metadata of the image and
// encryption details such as key URL, digest etc.
type Image struct {
	Meta               Meta        `json:"meta"`
	EncryptionRequired bool        `json:"encryption_required"`
	Encryption         *Encryption `json:"encryption,omitempty"`
	IntegrityEnforced  bool        `json:"integrity_enforced"`
	Integrity          *Integrity  `json:"integrity,omitempty"`
}

// SignedImageFlavor struct defines the image flavor and
// its corresponding signature
type SignedImageFlavor struct {
	ImageFlavor Image  `json:"flavor"`
	Signature   string `json:"signature"`
}

type FlavorImage struct {
	Image Image `json:"flavor"`
}
