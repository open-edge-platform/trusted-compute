/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestGetHexRandomString(t *testing.T) {
	type args struct {
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Valid get random string",
			args: args{
				length: 4,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetHexRandomString(tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHexRandomString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetHashingAlgorithmName(t *testing.T) {
	type args struct {
		alg crypto.Hash
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Sha algorithm name - SHA1",
			args: args{
				alg: crypto.SHA1,
			},
			want: "SHA1",
		},
		{
			name: "Sha algorithm name - SHA256",
			args: args{
				alg: crypto.SHA256,
			},
			want: "SHA-256",
		},
		{
			name: "Sha algorithm name - SHA384",
			args: args{
				alg: crypto.SHA384,
			},
			want: "SHA-384",
		},
		{
			name: "Sha algorithm name - SHA512",
			args: args{
				alg: crypto.SHA512,
			},
			want: "SHA-512",
		},
		{
			name: "Invalid sha algorithm name",
			args: args{
				alg: crypto.MD5SHA1,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHashingAlgorithmName(tt.args.alg); got != tt.want {
				t.Errorf("GetHashingAlgorithmName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHashData(t *testing.T) {
	type args struct {
		data []byte
		alg  crypto.Hash
	}
	sha1Sum := sha1.Sum([]byte("Test"))
	sha256Sum := sha256.Sum256([]byte("Test"))
	sha384Sum := sha512.Sum384([]byte("Test"))
	sha512Sum := sha512.Sum512([]byte("Test"))

	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Get hash data with - SHA1",
			args: args{
				data: []byte("Test"),
				alg:  crypto.SHA1,
			},
			want:    sha1Sum[:],
			wantErr: false,
		},
		{
			name: "Get hash data with - SHA256",
			args: args{
				data: []byte("Test"),
				alg:  crypto.SHA256,
			},
			want:    sha256Sum[:],
			wantErr: false,
		},
		{
			name: "Get hash data with - SHA384",
			args: args{
				data: []byte("Test"),
				alg:  crypto.SHA384,
			},
			want:    sha384Sum[:],
			wantErr: false,
		},
		{
			name: "Get hash data with - SHA512",
			args: args{
				data: []byte("Test"),
				alg:  crypto.SHA512,
			},
			want:    sha512Sum[:],
			wantErr: false,
		},
		{
			name: "Get hash data with invalid data",
			args: args{
				data: nil,
				alg:  crypto.SHA512,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Get hash data with invalid sha algorithm",
			args: args{
				data: []byte("Test"),
				alg:  crypto.MD5,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHashData(tt.args.data, tt.args.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHashData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHashData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateSelfSignedCertAndRSAPrivKeys(t *testing.T) {
	type args struct {
		bits []int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "CreateSelfSignedCertAndRSAPrivKeys with provided rsa key length",
			args: args{
				bits: []int{1024},
			},
			wantErr: false,
		},
		{
			name: "CreateSelfSignedCertAndRSAPrivKeys with default rsa key length",
			args: args{
				bits: nil,
			},
			wantErr: false,
		},
		{
			name: "Invalid CreateSelfSignedCertAndRSAPrivKeys with multiple parameter",
			args: args{
				bits: []int{1, 2, 3, 4},
			},
			wantErr: true,
		},
		{
			name: "CreateSelfSignedCertAndRSAPrivKeys with invalid rsa key length",
			args: args{
				bits: []int{1031},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := CreateSelfSignedCertAndRSAPrivKeys(tt.args.bits...)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSelfSignedCertAndRSAPrivKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestHashAndSignPKCS1v15(t *testing.T) {
	type args struct {
		data    []byte
		rsaPriv *rsa.PrivateKey
		alg     crypto.Hash
	}
	key, _, _ := CreateSelfSignedCertAndRSAPrivKeys(2048)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate HashAndSignPKCS1v15 with valid sha",
			args: args{
				data:    []byte{1, 5, 7, 89, 4, 6, 7, 5, 45, 67, 78},
				rsaPriv: key,
				alg:     crypto.SHA256,
			},
			wantErr: false,
		},
		{
			name: "Validate HashAndSignPKCS1v15 with invalid sha",
			args: args{
				data:    []byte{1, 5, 7, 89, 4, 6, 7, 5, 45, 67, 78},
				rsaPriv: key,
				alg:     crypto.MD5,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashAndSignPKCS1v15(tt.args.data, tt.args.rsaPriv, tt.args.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashAndSignPKCS1v15() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetCertHexSha384(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "GetCertHexSha384 with Valid data",
			args: args{
				filePath: "test_data/cert/e36663d78.pem",
			},
			want:    "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
			wantErr: false,
		},
		{
			name: "Validate GetCertHexSha384 when cert file does not exist",
			args: args{
				filePath: "test_data/test_file.pem",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Validate GetCertHexSha384 with invalid file",
			args: args{
				filePath: "test_data/test.pem",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Validate GetCertHexSha384 with invalid certs",
			args: args{
				filePath: "test_data/invalid_cert.pem",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetCertHexSha384(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertHexSha384() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetCertHexSha384() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAesEncrypt(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Encrypt aes data ",
			args: args{
				data: []byte("Test data"),
				key:  []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AesEncrypt(tt.args.data, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("AesEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAesDecrypt(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
	}
	Data, err := hex.DecodeString("33e39b0ab0fa177185e1f9e0bb0071ca7c67cd2deb3a9b4b87d5fe27dbad8ea6e2db5cca2d")
	if err != nil {
		t.Error("Error in decoding string")
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Decrypt aes data",
			args: args{
				data: Data,
				key:  []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
			},
			want:    []byte("Test data"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AesDecrypt(tt.args.data, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("AesDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AesDecrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
