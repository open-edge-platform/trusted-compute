/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package jwtauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultTokenValidity    = 24 * time.Hour
	gracePeriodForClockSkew = 30 * time.Second
)

type MatchingCertNotFoundError struct {
	KeyId string
}

func (e MatchingCertNotFoundError) Error() string {
	return fmt.Sprintf("certificate with matching public key not found. kid (key id) : %s", e.KeyId)
}

type MatchingCertJustExpired struct {
	KeyId string
}

func (e MatchingCertJustExpired) Error() string {
	return fmt.Sprintf("certificate with matching public key just expired. kid (key id) : %s", e.KeyId)
}

type VerifierExpiredError struct {
	expiry time.Time
}

func (e VerifierExpiredError) Error() string {
	return fmt.Sprintf("verifier expired at %v", e.expiry)
}

type NoValidCertFoundError struct {
}

func (e NoValidCertFoundError) Error() string {
	return fmt.Sprintf("there are no valid certificates when initializing jwt verifier")
}

type JwtFactory struct {
	privKey       crypto.PrivateKey
	issuer        string
	tokenValidity time.Duration
	signingMethod jwt.SigningMethod
	keyId         string
}

type RegisteredClaims jwt.RegisteredClaims
type CustomClaims interface{}

type claims struct {
	jwt.RegisteredClaims
	customClaims interface{}
}

// GetAudience implements the jwt.Claims interface for the claims struct.
func (c claims) GetAudience() (jwt.ClaimStrings, error) {
	return c.RegisteredClaims.Audience, nil
}

type Token struct {
	jwtToken         *jwt.Token
	RegisteredClaims *jwt.RegisteredClaims
	customClaims     interface{}
}

func (t *Token) GetClaims() interface{} {
	return t.customClaims
}

func (t *Token) GetAllClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.jwtToken.Claims
}

func (t *Token) GetRegisteredClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.RegisteredClaims
}

func (t *Token) GetHeader() *map[string]interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return &t.jwtToken.Header
}

func (t *Token) GetSubject() string {
	if t.RegisteredClaims == nil {
		return ""
	}
	return t.RegisteredClaims.Subject
}

type verifierKey struct {
	pubKey  crypto.PublicKey
	expTime time.Time
}

type verifierPrivate struct {
	expiration   time.Time
	pubKeyMapMtx sync.RWMutex
	pubKeyMap    map[string]verifierKey
}

type Verifier interface {
	ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error)
}

func getJwtSigningMethod(privKey crypto.PrivateKey) (jwt.SigningMethod, error) {

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		bitLen := key.N.BitLen()
		if bitLen != 3072 && bitLen != 4096 {
			return nil, fmt.Errorf("RSA keylength for JWT signing must be 3072 or 4096")
		}
		return jwt.GetSigningMethod("RS384"), nil
	case *ecdsa.PrivateKey:
		bitLen := key.Curve.Params().BitSize
		if bitLen != 256 && bitLen != 384 {
			return nil, fmt.Errorf("RSA keylength for JWT signing must be 256 or 384")
		}
		if bitLen == 384 {
			return jwt.GetSigningMethod("ES384"), nil
		}
		return jwt.GetSigningMethod("ES256"), nil
	default:
		return nil, fmt.Errorf("unsupported key type for JWT signing. only RSA and ECDSA supported")
	}

}

// NewTokenFactory method allows to create a factory object that can be used to generate the token.
// basically, it allows to load the private key just once and keep using it. The issuer and default
// validity can be passed in so that these do not have to be passed in every time.
func NewTokenFactory(pkcs8der []byte, includeKeyIdInToken bool, signingCertPem []byte, issuer string, tokenValidity time.Duration) (*JwtFactory, error) {
	if tokenValidity == 0 {
		tokenValidity = defaultTokenValidity
	}

	key, err := x509.ParsePKCS8PrivateKey(pkcs8der)
	if err != nil {
		return nil, err
	}
	signingMethod, err := getJwtSigningMethod(key)
	if err != nil {
		return nil, err
	}

	var keyId string

	//todo - we need to decide if we should use the information in the cert
	if includeKeyIdInToken && len(signingCertPem) > 0 {
		block, _ := pem.Decode(signingCertPem)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("NewTokenFactory: failed to parse signing certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("NewTokenFactory: failed to parse certificate: " + err.Error())
		}
		hash, _ := crypt.GetHashData(cert.Raw, crypto.SHA1)
		keyId = hex.EncodeToString(hash)

	}

	return &JwtFactory{privKey: key,
		issuer:        issuer,
		tokenValidity: tokenValidity,
		signingMethod: signingMethod,
		keyId:         keyId,
	}, nil
}

// We are doing custom marshalling here to combine the standard attributes of a JWT and the claims
// that we want to add. Everything would be at the top level. For instance, if we want to carry
func (c claims) MarshalJSON() ([]byte, error) {

	slice1, err := json.Marshal(c.customClaims)
	if err != nil {
		return nil, err
	}
	slice2, err := json.Marshal(c.RegisteredClaims)
	if err != nil {
		return nil, err
	}
	slice1[len(slice1)-1] = ','
	slice2[0] = ' '
	return append(slice1, slice2...), nil
}

// Create generates a token based on the claims structure passed in. We collapse the claims with the standard
// jwt claims. Each client need only worry about what he would like to include in the claims.
// Of course the token is signed as well.
func (f *JwtFactory) Create(clms interface{}, subject string, validity time.Duration) (string, error) {
	if validity == 0 {
		validity = f.tokenValidity
	}
	now := time.Now()

	jwtclaim := claims{}
	// allow for a clock skew as issuing server time might be ahead of services validating the token
	jwtclaim.RegisteredClaims.IssuedAt = jwt.NewNumericDate(now.Add(-1 * gracePeriodForClockSkew))
	jwtclaim.RegisteredClaims.NotBefore = jwtclaim.RegisteredClaims.IssuedAt
	jwtclaim.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(validity))
	jwtclaim.RegisteredClaims.Issuer = f.issuer
	jwtclaim.RegisteredClaims.Subject = subject

	jwtclaim.customClaims = clms
	token := jwt.NewWithClaims(f.signingMethod, jwtclaim)
	if f.keyId != "" {
		token.Header["kid"] = f.keyId
	}
	return token.SignedString(f.privKey)

}

//TODO: move to common crypto

// TODO - implement this to parse the claims
func (v *verifierPrivate) ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error) {

	// let us check if the verifier is already expired. If it is just return verifier expired error
	// The caller has to re-initialize the verifier.
	token := Token{}
	token.RegisteredClaims = &jwt.RegisteredClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, token.RegisteredClaims, func(token *jwt.Token) (interface{}, error) {

		if keyIDValue, keyIDExists := token.Header["kid"]; keyIDExists {

			keyIDString, ok := keyIDValue.(string)
			if !ok {
				return nil, fmt.Errorf("kid (key id) in jwt header is not a string : %v", keyIDValue)
			}

			v.pubKeyMapMtx.RLock()
			defer v.pubKeyMapMtx.RUnlock()
			if matchPubKey, found := v.pubKeyMap[keyIDString]; !found {
				return nil, &MatchingCertNotFoundError{keyIDString}
			} else {
				// if the certificate just expired.. we need to return appropriate error
				// so that the caller can deal with it appropriately
				now := time.Now()
				if now.After(matchPubKey.expTime) {
					return nil, &MatchingCertJustExpired{keyIDString}
				}
				// if the verifier expired, we need to use a new instance of the verifier
				if time.Now().After(v.expiration) {
					return nil, &VerifierExpiredError{v.expiration}
				}
				return matchPubKey.pubKey, nil
			}

		} else {
			return nil, fmt.Errorf("kid (key id) field missing in token. field is mandatory")
		}
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrTokenUnverifiable) {
			var innerErr error
			if errors.As(err, &innerErr) {
				switch e := innerErr.(type) {
				case *MatchingCertNotFoundError, *VerifierExpiredError, *MatchingCertJustExpired:
					return nil, e
				}
			}
			return nil, err
		}
		return nil, err
	}
	token.jwtToken = parsedToken
	// so far we have only got the RegisteredClaims parsed. We need to now fill the customClaims

	// Removed unused variable 'parts'
	// no need check for the number of segments since the previous ParseWithClaims has already done this check.
	// therefor the following is redundant. If we change the implementation, will need to revisit
	//if len(parts) != 3 {
	//	return nil, "jwt token to be parsed seems to be in "
	//}

	// parse Claims
	// Removed unused variable 'claimBytes'

	parser := jwt.NewParser()
	_, _, err = parser.ParseUnverified(tokenString, jwt.MapClaims(customClaims.(map[string]interface{})))
	if err != nil {
		return nil, fmt.Errorf("could not parse claims part of the jwt token: %v", err)
	}
	token.customClaims = customClaims
	token.customClaims = customClaims

	return &token, nil
}

func NewVerifier(signingCertPems interface{}, rootCAPems [][]byte, cacheTime time.Duration) (Verifier, error) {

	v := verifierPrivate{expiration: time.Now().Add(cacheTime)}
	v.pubKeyMap = make(map[string]verifierKey)

	var certPemSlice [][]byte

	switch signingCertPems.(type) {
	case nil:
		return &v, nil
	case [][]byte:
		certPemSlice = signingCertPems.([][]byte)
	case []byte:
		certPemSlice = [][]byte{signingCertPems.([]byte)}
	default:
		return nil, fmt.Errorf("signingCertPems has to be of type []byte or [][]byte")

	}
	// build the trust root CAs first
	roots := x509.NewCertPool()
	for _, rootPEM := range rootCAPems {
		roots.AppendCertsFromPEM(rootPEM)
	}

	verifyRootCAOpts := x509.VerifyOptions{
		Roots: roots,
	}

	for _, certPem := range certPemSlice {
		// TODO - we should validate the certificate here as well
		// we might just want to take the certificate from the pem here itself
		// then retrieve the public key, hash and also do the verification right
		// here. Otherwise we are parsing the certificate multiple times.
		var cert *x509.Certificate
		var err error
		cert, verifyRootCAOpts.Intermediates, err = crypt.GetCertAndChainFromPem(certPem)
		if err != nil || time.Now().After(cert.NotAfter) { // expired certificate
			continue
		}

		// if certificate is not self signed, then we have to validate the cert
		// this implies that we are allowing self signed certificate.
		if !(cert.IsCA && cert.BasicConstraintsValid) {
			if _, err := cert.Verify(verifyRootCAOpts); err != nil {
				continue
			}
		}

		certHash, err := crypt.GetCertHashInHex(cert, crypto.SHA1)
		if err != nil {
			continue
		}
		pubKey, err := crypt.GetPublicKeyFromCert(cert)
		if err != nil {
			continue
		}
		v.pubKeyMapMtx.Lock()
		v.pubKeyMap[certHash] = verifierKey{pubKey: pubKey, expTime: cert.NotAfter}
		v.pubKeyMapMtx.Unlock()
		// update the validity of the object if the certificate expires before the current validity
		// TODO: set the expiration when based on CRL when it become available
		if v.expiration.After(cert.NotAfter) {
			v.expiration = cert.NotAfter
		}
	}
	// we will return a valid object at this point.. it still might not contain any valid certificates
	return &v, nil

}
