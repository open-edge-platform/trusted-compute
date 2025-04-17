/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package jwtauth

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestMatchingCertNotFoundError_Error(t *testing.T) {
	type fields struct {
		KeyId string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Validate MatchingCertNotFoundError with valid data",
			fields: fields{
				KeyId: "494cd783-46c2-4f4a-8faf-55415cf85fe0",
			},
			want: "certificate with matching public key not found. kid (key id) : 494cd783-46c2-4f4a-8faf-55415cf85fe0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := MatchingCertNotFoundError{
				KeyId: tt.fields.KeyId,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("MatchingCertNotFoundError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchingCertJustExpired_Error(t *testing.T) {
	type fields struct {
		KeyId string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Validate MatchingCertJustExpired with valid data",
			fields: fields{
				KeyId: "494cd783-46c2-4f4a-8faf-55415cf85fe0",
			},
			want: "certificate with matching public key just expired. kid (key id) : 494cd783-46c2-4f4a-8faf-55415cf85fe0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := MatchingCertJustExpired{
				KeyId: tt.fields.KeyId,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("MatchingCertJustExpired.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifierExpiredError_Error(t *testing.T) {
	type fields struct {
		expiry time.Time
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Validate VerifierExpiredError with valid data",
			fields: fields{
				expiry: time.Date(
					2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			},
			want: "verifier expired at 2009-11-17 20:34:58.651387237 +0000 UTC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := VerifierExpiredError{
				expiry: tt.fields.expiry,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("VerifierExpiredError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoValidCertFoundError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    NoValidCertFoundError
		want string
	}{
		{
			name: "Validate NoValidCertFoundError with valid data",
			e:    NoValidCertFoundError{},
			want: "there are no valid certificates when initializing jwt verifier",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NoValidCertFoundError{}
			if got := e.Error(); got != tt.want {
				t.Errorf("NoValidCertFoundError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_GetClaims(t *testing.T) {
	type fields struct {
		jwtToken       *jwt.Token
		standardClaims *jwt.StandardClaims
		customClaims   interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   interface{}
	}{
		{
			name: "Validate Token_GetClaims",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				jwtToken:       tt.fields.jwtToken,
				standardClaims: tt.fields.standardClaims,
				customClaims:   tt.fields.customClaims,
			}
			if got := tr.GetClaims(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Token.GetClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_GetAllClaims(t *testing.T) {
	type fields struct {
		jwtToken       *jwt.Token
		standardClaims *jwt.StandardClaims
		customClaims   interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   interface{}
	}{
		{
			name: "Validate Token_GetAllClaims with valid data",
			fields: fields{
				jwtToken: nil,
			},
			want: nil,
		},
		{
			name: "Validate Token_GetAllClaims with nil claims",
			fields: fields{
				jwtToken: &jwt.Token{
					Claims: nil,
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				jwtToken:       tt.fields.jwtToken,
				standardClaims: tt.fields.standardClaims,
				customClaims:   tt.fields.customClaims,
			}
			if got := tr.GetAllClaims(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Token.GetAllClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_GetStandardClaims(t *testing.T) {
	type fields struct {
		jwtToken       *jwt.Token
		standardClaims *jwt.StandardClaims
		customClaims   interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   interface{}
	}{
		{
			name: "Validate Token_GetStandardClaims with nil jwt token",
			fields: fields{
				jwtToken: nil,
			},
			want: nil,
		},
		{
			name: "Validate Token_GetStandardClaims with valid jwt token",
			fields: fields{
				jwtToken:       &jwt.Token{},
				standardClaims: &jwt.StandardClaims{},
			},
			want: &jwt.StandardClaims{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				jwtToken:       tt.fields.jwtToken,
				standardClaims: tt.fields.standardClaims,
				customClaims:   tt.fields.customClaims,
			}
			if got := tr.GetStandardClaims(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Token.GetStandardClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_GetHeader(t *testing.T) {
	type fields struct {
		jwtToken       *jwt.Token
		standardClaims *jwt.StandardClaims
		customClaims   interface{}
	}
	jwttoken := jwt.Token{}
	tests := []struct {
		name   string
		fields fields
		want   *map[string]interface{}
	}{
		{
			name: "Validate Token_GetHeader with nil jwt token",
			fields: fields{
				jwtToken: nil,
			},
			want: nil,
		},
		{
			name: "Validate Token_GetHeader with valid jwt token",
			fields: fields{
				jwtToken: &jwt.Token{
					Header: nil,
				},
			},
			want: &jwttoken.Header,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				jwtToken:       tt.fields.jwtToken,
				standardClaims: tt.fields.standardClaims,
				customClaims:   tt.fields.customClaims,
			}
			if got := tr.GetHeader(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Token.GetHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_GetSubject(t *testing.T) {
	type fields struct {
		jwtToken       *jwt.Token
		standardClaims *jwt.StandardClaims
		customClaims   interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Validate Token_GetSubject with nil standard claims",
			fields: fields{
				standardClaims: nil,
			},
			want: "",
		},
		{
			name: "Validate Token_GetSubject with standard claims data",
			fields: fields{
				standardClaims: &jwt.StandardClaims{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				jwtToken:       tt.fields.jwtToken,
				standardClaims: tt.fields.standardClaims,
				customClaims:   tt.fields.customClaims,
			}
			if got := tr.GetSubject(); got != tt.want {
				t.Errorf("Token.GetSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getJwtSigningMethod(t *testing.T) {
	type args struct {
		privKey crypto.PrivateKey
	}
	validPrivatekey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	invalidPrivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	validecdsa256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Cannot generate ECDSA key\n")
		os.Exit(1)
	}
	validecdsa384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Cannot generate ECDSA key\n")
		os.Exit(1)
	}
	invalidecdsa521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		fmt.Printf("Cannot generate ECDSA key\n")
		os.Exit(1)
	}
	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dsaprivatekey := new(dsa.PrivateKey)
	dsaprivatekey.PublicKey.Parameters = *params
	dsa.GenerateKey(dsaprivatekey, rand.Reader) // this generates a public & private key pair
	tests := []struct {
		name    string
		args    args
		want    jwt.SigningMethod
		wantErr bool
	}{
		{
			name: "Validate with valid RSA private key",
			args: args{
				privKey: validPrivatekey,
			},
			want:    jwt.GetSigningMethod("RS384"),
			wantErr: false,
		},
		{
			name: "Validate with invalid RSA private key",
			args: args{
				privKey: invalidPrivatekey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Validate with valid ECDSA256 private key",
			args: args{
				privKey: validecdsa256Key,
			},
			want:    jwt.GetSigningMethod("ES256"),
			wantErr: false,
		},
		{
			name: "Validate with valid ECDSA384 private key",
			args: args{
				privKey: validecdsa384Key,
			},
			want:    jwt.GetSigningMethod("ES384"),
			wantErr: false,
		},
		{
			name: "Validate with invalid ECDSA private key",
			args: args{
				privKey: invalidecdsa521Key,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Validate with invalid dsa private key",
			args: args{
				privKey: dsaprivatekey,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getJwtSigningMethod(tt.args.privKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getJwtSigningMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getJwtSigningMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTokenFactory(t *testing.T) {
	type args struct {
		pkcs8der            []byte
		includeKeyIdInToken bool
		signingCertPem      []byte
		issuer              string
		tokenValidity       time.Duration
	}
	pkcs8KeyBlock, _ := pem.Decode([]byte(pkcs8Key))
	if pkcs8KeyBlock == nil {
		panic("failed to decode a pem block from private key pem")
	}

	validRSAKeyBlock, _ := pem.Decode([]byte(validRSAKey))
	if validRSAKeyBlock == nil {
		panic("failed to decode a pem block from private key pem")
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate NewTokenFactory with empty rsa key",
			args: args{
				tokenValidity: 0,
			},
			wantErr: true,
		},
		{
			name: "Validate NewTokenFactory with invalid rsa key length",
			args: args{
				tokenValidity: 0,
				pkcs8der:      pkcs8KeyBlock.Bytes,
			},
			wantErr: true,
		},
		{
			name: "Validate NewTokenFactory with valid rsa key length",
			args: args{
				tokenValidity: 0,
				pkcs8der:      validRSAKeyBlock.Bytes,
			},
			wantErr: false,
		},
		{
			name: "Validate NewTokenFactory with valid rsa key length and cert",
			args: args{
				tokenValidity:       0,
				pkcs8der:            validRSAKeyBlock.Bytes,
				includeKeyIdInToken: true,
				signingCertPem:      []byte(certificate),
			},
			wantErr: false,
		},
		{
			name: "Validate NewTokenFactory with Empty cert",
			args: args{
				tokenValidity:       0,
				pkcs8der:            validRSAKeyBlock.Bytes,
				includeKeyIdInToken: true,
				signingCertPem:      []byte("Cert"),
			},
			wantErr: true,
		},
		{
			name: "Validate NewTokenFactory with invalid cert",
			args: args{
				tokenValidity:       0,
				pkcs8der:            validRSAKeyBlock.Bytes,
				includeKeyIdInToken: true,
				signingCertPem:      []byte(invalidCertificate),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTokenFactory(tt.args.pkcs8der, tt.args.includeKeyIdInToken, tt.args.signingCertPem, tt.args.issuer, tt.args.tokenValidity)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenFactory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_claims_MarshalJSON(t *testing.T) {
	type fields struct {
		StandardClaims jwt.StandardClaims
		customClaims   interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate claims_MarshalJSONs",
			fields: fields{
				StandardClaims: jwt.StandardClaims{},
				customClaims:   nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := claims{
				StandardClaims: tt.fields.StandardClaims,
				customClaims:   tt.fields.customClaims,
			}
			_, err := c.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("claims.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var pkcs8Key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCT3O/qC06UUu54
SGM3hZy6c0ipXIxCxjqS3RGF5q7+UFMwjjCzXHrTfZ6K7vxiEYZo56/OjXpd19K3
7SwsFrlgHUpXBRez2F/dsgy8pvt0uazL5eUqGYE79uqN6RhX0JiMpoY6qsflNPee
ZBJOx7s++YnyQvS/mYZMHtsfGvY8liK3lT3fNtzZtGsF0uY3JlBgkxqQ7vdl6ohL
3HKTbf7niRV8dqQZGyDxOfkBEdif66MkPcyLfQ3F2s8CtKrvGdwPDitjW9cxlH8k
tv9gxACDFtAWnry8izCpgQNNISHDI/SZ8Rf80G0ql3BsPzF66cX5BSVpwmNP0kSE
+4Dggfw7AgMBAAECggEAKH+U/oeGSD3Grw80jZp86Nx2hFyi1g8xL9R43jHmsCUU
A/KOCDJGOfLoH6mBWuLt64G5t1ssrtNUFahSNukqcNbU66yrZ0jWSQRhVLJvoPLS
Dy6ya6t8qA3jBGdZkYPCpJNfpGXuRisRv0IteYJfGMqEK+SG4IuOKv8wiP57fvA9
kcesFszv94ALLB/TjEkr4wRE0AiU65W+XFvgsgeI8br7FanNCF4V1610r3hfRbjk
a3X5JsUszXQWTnxYv5tG8SLxjTAjF7dsDE96wDXpZ41e6ZZb1k661tC+83ykuxlz
D9waP1yu7xeYSFD693bkKfl9CXVRnNn5UT9BS4h2oQKBgQDDuCtgKdeeaIpXyoxl
TBZDSbb+3Y4G3cUkVjFvhcwHvtVmmdegDLsTqEWapnE0WDRGBVz4bfFdi1Z5XTEO
ckYvsI6EaBW3Bo1koDfNXNxT2hHhm2fIVJOoEXvnXLmx7a2IbP4xyd3CHh0Cjx9Z
AMOCqmTuqQPR1VB0EmbPqEsf8wKBgQDBZ3NAkJcjrjvADdn5xXycGrVRhUO3vSIy
U7UJh4oiYgHMQWSISB3J1HICm9FK4rYp6mOZ1LhVg6rfm34z5FbCo+X8Q/TqLMKm
bhWAAN88p8gcykOgn2FeW1PWewjvT1ArhbKpkLhydgIgDWztQ7py302Jr66jBKc0
1WDxTRGMmQKBgAfCN0X6oqeO8V0FlIc3evJz66My2TyAch48pH0NSsdL013b32Zi
2s+urgOxcW9nx7q237ahdR4GNgldnmI6OXoOf7fUAHhe9B/3Ef88HSfdzzOoW3bf
k3LoLoc/b8UT7PsphvImVHorg27kiZOXqih15MZpQNOCp0vSpuy4eTHtAoGAN/YK
CC2OPfnFOi4H21jEVJr5ygvIa1rjkTJdWNOKKaa4JHTrdO+BBwxcrNqPNZ7h3MEA
btt5Nu0xPSBN5Q/19r3b5yF2tWecLvH9cJtP/MoDgikYZlqXnujIGnBhRnVpmh5G
cv/4Ds6MkN+xm/mT8ncghW17F5paE1SGh2uoX0kCgYEAuf5fYLyTw48unXO1hyFu
fBB/+QZpfqIqZxmweJxD0zX35dGO0F2zs1H0Ob7fRP0z4dqrXzyROCzNpPq5VJG8
w6LOfaPU795axQLDVfa0Hxp+p1aqn04HbatSePbDsWv2tP21ZJZRLcxnYMlaJPSu
KiElKOVAmMLlRxie4xWNR10=
-----END PRIVATE KEY-----`

var validRSAKey = `-----BEGIN PRIVATE KEY-----
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
SiepVYgA7HLwP5jxNYOk9ybNueNyNSI=
-----END PRIVATE KEY-----`

var certificate = `-----BEGIN CERTIFICATE-----
MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
-----END CERTIFICATE-----`

var invalidCertificate = `-----BEGIN CERTIFICATE-----
MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmwc9ss3qlYrEPldUPMxzuRxqrQZr0
g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
-----END CERTIFICATE-----`
