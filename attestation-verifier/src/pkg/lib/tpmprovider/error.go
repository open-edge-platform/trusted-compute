/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import (
	"fmt"
)

var errorMessageMap = map[int]string{
	TPM_PROVIDER_ERROR_NO_EK_CERT:     "The TPM does not have an EK Certificate",
	TPM_PROVIDER_EK_PUBLIC_MISMATCH:   "EK generation failed: The EK does not have a public key that matches the EK Certificate's",
	TPM_PROVIDER_INVALID_PCRSELECTION: "Invalid PCR Selection parameters supplied",
	TPM_PROVIDER_INVALID_PCRCOUNT:     "Invalid number of banks in response",
}

// TpmProviderError maps error messages to error codes returned from the tpm-provider's
// cgo functions.
type TpmProviderError struct {
	ErrorCode int
	Message   string
}

func (e *TpmProviderError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func NewTpmProviderError(errorCode int) *TpmProviderError {

	var message string
	if lookup, ok := errorMessageMap[errorCode]; ok {
		message = lookup
	} else {
		message = ""
	}

	return &TpmProviderError{
		ErrorCode: errorCode,
		Message:   message,
	}
}
