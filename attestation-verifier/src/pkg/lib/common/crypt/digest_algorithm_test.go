/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"
	"testing"
)

func TestDigestAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		d    DigestAlgorithm
		want string
	}{
		{
			name: "Validate DigestAlgorithm for sha256",
			d: DigestAlgorithm{
				Name: "sha256",
			},
			want: "SHA256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("DigestAlgorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDigestAlgorithm_Prefix(t *testing.T) {
	tests := []struct {
		name string
		d    DigestAlgorithm
		want string
	}{
		{
			name: "Validate DigestAlgorithm prefix for sha256",
			d: DigestAlgorithm{
				Name: "sha256",
			},
			want: "sha256:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.Prefix(); got != tt.want {
				t.Errorf("DigestAlgorithm.Prefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMD5(t *testing.T) {
	tests := []struct {
		name string
		want DigestAlgorithm
	}{
		{
			name: "Validate MD5 algorithm name",
			want: DigestAlgorithm{
				Algorithm: crypto.MD5,
				Length:    md5.Size,
				Name:      "MD5",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MD5(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MD5() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA1(t *testing.T) {
	tests := []struct {
		name string
		want DigestAlgorithm
	}{
		{
			name: "Validate sha1 algorithm name",
			want: DigestAlgorithm{
				Algorithm: crypto.SHA1,
				Length:    sha1.Size,
				Name:      "SHA1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SHA1(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SHA1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA256(t *testing.T) {
	tests := []struct {
		name string
		want DigestAlgorithm
	}{
		{
			name: "Validate sha256 algorithm name",
			want: DigestAlgorithm{
				Algorithm: crypto.SHA256,
				Length:    sha256.Size,
				Name:      "SHA256",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SHA256(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SHA256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA384(t *testing.T) {
	tests := []struct {
		name string
		want DigestAlgorithm
	}{
		{
			name: "Validate sha384 algorithm name",
			want: DigestAlgorithm{
				Algorithm: crypto.SHA384,
				Length:    sha512.Size384,
				Name:      "SHA384",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SHA384(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SHA384() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA512(t *testing.T) {
	tests := []struct {
		name string
		want DigestAlgorithm
	}{
		{
			name: "Validate sha512 algorithm name",
			want: DigestAlgorithm{
				Algorithm: crypto.SHA512,
				Length:    sha512.Size,
				Name:      "SHA512",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SHA512(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SHA512() = %v, want %v", got, tt.want)
			}
		})
	}
}
