/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

// {
// 	           "secret"        :      "AAGB9Xr+ti6dsDSph9FqM1tOM8LLWLLhUhb89R6agQ/hA+eQDF2FpcfOM/98J95ywwYpxzYS8N
// 	                                   x6c7ud5e6SVVgLldcc3/m9xfsCC7tEmfQRyc+pydbgnCHQ9E/TQoyV/VgiE5ssV+lGX171+lN+
// 	                                   2RSO0HC8er+jN52bh31M4S09sv6+Qk2Fm2efDsF2NbFI4eyLcmtFEwKfDyAiZ3zeXqPNQWpUzV
// 	                                   ZzR3zfxpd6u6ZonYmfOn/fLDPIHwTFv8cYHSIRailTQXP+VmQuyR7YOI8oe/NC/cr7DIYTJD7G
// 	                                   LFNDXk+sybf9j9Ttng4RRyb0WXgIcfIWW1oZD+i4wqu9OdV1",
// 	           "credential"    :      "NAAAIBVuOfmXFbgcbBA2fLtnl38KQ7fIRGwUSf5kQ+UwIAw8ElXsYfoBoUB11BWKkc4uo9WRAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
// 	           "sym_blob"      :      "AAAAQAAAAAYAAQAAAAAAAMlZgTkKMlujW0vDUrhcE8Ixut12y5yXXP7nyx8wSUSHIaNz419fpy
// 	                                   AiQdsCG3PMJGvsNtiInB1zjGqQOtt77zM=",
// 	           "ek_blob"       :      "Tb3zQv6oW8/dUg45qofJFsIZV1XHTADZgeVjH7BI/ph+6ERJTlxBjK7zkxHJh54QlCi5h0f1rM
// 	                                   kYqtAyCmmyyUdewP4xFaVmjm8JcWaAzeOfb3vhamWr9xGecfJ34D58cy2Att7VAzXoWe2GthAb
// 	                                   lM+Rjsy9wiXfyOe9IjfC5jngjPHfwyi8IvV+FZHTG8wq7R8lcAQdurMmOzMZJT+vkzBq1TEGLu
// 	                                   rE3h4Rf84X3H/um4sQ2mqo+r5ZIsm+6lhb6PjU4S9Cp3j4RZ5nU/uVvgTWzviNUPYBbd3AypQo
// 	                                   9Kv5ij8UqHk2P1DzWjCBvwCqHTzRsuf9b9FeT+f4aWgLNQ=="
// 	}
type IdentityProofRequest struct {
	Secret                []byte                `json:"secret"`
	Credential            []byte                `json:"credential"`
	TpmSymmetricKeyParams TpmSymmetricKeyParams `json:"symmetric_params"`
	SymmetricBlob         []byte                `json:"symmetric_blob"`
}

type IdentityRequest struct {
	TpmVersion string `json:"tpm_version"`
	AikModulus []byte `json:"aik_modulus"`
	AikName    []byte `json:"aik_name"`
}

type IdentityChallengePayload struct {
	IdentityRequest        IdentityRequest        `json:"identity_request"`
	TpmAsymmetricKeyParams TpmAsymmetricKeyParams `json:"tpm_asymmetric_params"`
	TpmSymmetricKeyParams  TpmSymmetricKeyParams  `json:"tpm_symmetric_params"`
	SymBlob                []byte                 `json:"symblob"`
	AsymBlob               []byte                 `json:"asymblob"`
}

type TpmAsymmetricKeyParams struct {
	TpmAlgId              int
	TpmAlgEncScheme       int
	TpmAlgSignatureScheme int
	KeyLength             int
	PrimesCount           int
	ExponentSize          int
}

type TpmSymmetricKeyParams struct {
	TpmAlgId              int
	TpmAlgEncScheme       int
	TpmAlgSignatureScheme int
	KeyLength             int
	BlockSize             int
	IV                    []byte
}
