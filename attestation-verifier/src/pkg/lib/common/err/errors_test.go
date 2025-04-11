/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package err

import (
	"testing"
)

func TestHandledError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    HandledError
		want string
	}{
		{
			name: "Validate HandledError for not authorized",
			e: HandledError{
				StatusCode: 401,
				Message:    "Not authorized error",
			},
			want: "401: Not authorized error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("HandledError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivilegeError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    PrivilegeError
		want string
	}{
		{
			name: "Validate PrivilegeError",
			e: PrivilegeError{
				StatusCode: 401,
				Message:    "Not authorized error",
			},
			want: "401: Not authorized error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("PrivilegeError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    ServiceError
		want string
	}{
		{
			name: "Validate Service error",
			e: ServiceError{
				Message: "Service error",
			},
			want: "Service error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("ServiceError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpointError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    EndpointError
		want string
	}{
		{
			name: "Validate Endpoint error",
			e: EndpointError{
				Message: "Endpoint error",
			},
			want: "Endpoint error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("EndpointError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnsupportedMediaError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    UnsupportedMediaError
		want string
	}{
		{
			name: "Validate unsupported Media Error",
			e: UnsupportedMediaError{
				Message: "Unsupported Media Error",
			},
			want: "Unsupported Media Error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("UnsupportedMediaError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBadRequestError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    BadRequestError
		want string
	}{
		{
			name: "Validate Bad Request Error",
			e: BadRequestError{
				Message: "Bad Request Error",
			},
			want: "Bad Request Error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("BadRequestError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    StatusNotFoundError
		want string
	}{
		{
			name: "Validate Status Not Found Error",
			e: StatusNotFoundError{
				Message: "Status Not Found Error",
			},
			want: "Status Not Found Error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("StatusNotFoundError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    ResourceError
		want string
	}{
		{
			name: "Validate Resource Error",
			e: ResourceError{
				Message: "Resource Error",
			},
			want: "Resource Error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("ResourceError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
