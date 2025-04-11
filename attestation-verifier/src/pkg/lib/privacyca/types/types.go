/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package types

type Tpm2Credential struct {
	CredentialBlob []byte
	Secret         []byte
	HeaderBlob     []byte
}
