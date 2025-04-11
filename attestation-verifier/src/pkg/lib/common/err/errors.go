/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package err

import "fmt"

const (
	RecordNotFound = "record not found"
	RowsNotFound   = "no rows in result set"
)

type HandledError struct {
	StatusCode int
	Message    string
}

func (e HandledError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type PrivilegeError HandledError

func (e PrivilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type ServiceError struct {
	Message string
}

type UnsupportedMediaError ServiceError

type BadRequestError ServiceError

type StatusNotFoundError ServiceError

func (e ServiceError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

type ResourceError ServiceError

func (e ResourceError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

type EndpointError ServiceError

func (e EndpointError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func (e UnsupportedMediaError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func (e BadRequestError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func (e StatusNotFoundError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}
