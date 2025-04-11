/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	TPM2AlgorithmSymmetricAES   = "AES"
	SymmetricKeyBits128         = 128
	TPM_ALG_AES                 = 0x6
	TPM_ES_NONE                 = 0x1
	SHORT_BYTES                 = 2
	TPM_ALG_RSA                 = 1
	TPM_SS_NONE                 = 1
	TPM_ES_SYM_CBC_PKCS5PAD     = 255
	IDENTITY                    = "IDENTITY"
	STORAGE                     = "STORAGE"
	INTEGRITY                   = "INTEGRITY"
	TPM_ALG_ID_SHA256           = 0x000B
	TPM_ALG_ID_SHA384           = 0x000C
	HOST_KEYS_CERT_VALIDITY     = 10
	Tpm2NameDigestPrefixPadding = "22000b"
	Tpm2NameDigestSuffixPadding = "00000000000000000000000000000000000000000000000000000000000000000000"
)

var Tpm2CertifiedKeyType = [2]byte{0x80, 0x17}
var Tpm2CertifiedKeyMagic = [4]byte{0xff, 0x54, 0x43, 0x47}
