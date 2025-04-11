/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import "fmt"

/**
 *
 * @author mullas
 */

// ErrorCode implements Error interface and exports some standard error messages
// helpful during flavor-processing
type ErrorCode struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Implement the error interface
func (e ErrorCode) Error() string {
	return fmt.Sprintf("%s - %d", e.Message, e.Code)
}

func OK() ErrorCode { return ErrorCode{Code: 0, Message: "OK"} }
func SYSTEM_ERROR() ErrorCode {
	return ErrorCode{Code: 5001, Message: "System error. More information is available in the server log"}
}

func UNKNOWN_ERROR() ErrorCode {
	return ErrorCode{Code: 5002, Message: "Unknown error. More information is available in the server log"}
}
func TPM_VERSION_NOT_SUPPORTED_ERROR() ErrorCode {
	return ErrorCode{Code: 5003, Message: "This version of TPM is not supported by the platform"}
}
func UNKNOWN_FLAVOR_PART() ErrorCode {
	return ErrorCode{Code: 5004, Message: "Unknown flavor part specified"}
}
func UNKNOWN_VENDOR_SPECIFIED() ErrorCode {
	return ErrorCode{Code: 5005, Message: "Specified vendor is not supported"}
}
func UNSUPPORTED_OS() ErrorCode {
	return ErrorCode{Code: 5006, Message: "Host operating system is not supported"}
}
func INVALID_INPUT() ErrorCode { return ErrorCode{Code: 5007, Message: "Invalid input specified"} }

func FLAVOR_PART_CANNOT_BE_SUPPORTED() ErrorCode {
	return ErrorCode{Code: 5008, Message: "Requested flavor part cannot be supported. Please verify input parameters"}
}
func SOFTWARE_FLAVOR_CANNOT_BE_CREATED() ErrorCode {
	return ErrorCode{Code: 5009, Message: "No or invalid measurements, software flavor cannot be created"}
}
