/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/revoke"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func GenerateKeyPair(keyType string, keyLength int) (crypto.PrivateKey, crypto.PublicKey, error) {

	switch strings.ToLower(keyType) {
	case "rsa":
		if keyLength != 2048 && keyLength != 4096 {
			keyLength = 3072
		}
		k, err := rsa.GenerateKey(rand.Reader, keyLength)
		if err != nil {
			return nil, nil, fmt.Errorf("could not generate rsa key pair Error: %s", err)
		}
		return k, &k.PublicKey, nil
	// if the keytype is not "rsa", then we will always use ecdsa as this is the preferred
	//
	default:
		keyCurve := elliptic.P384()
		// below is not the correct check. we should check if the keylength == 521. But people might
		// be intending 512 for a stronger elliptical curve or 4096 which is meant for RSA.
		// so we will just check for keyLength >= 512
		if keyLength >= 512 {
			keyCurve = elliptic.P521()
		}
		k, err := ecdsa.GenerateKey(keyCurve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("could not generate ecdsa key pair Error: %s", err)
		}
		return k, &k.PublicKey, nil
	}

}

func GetSignatureAlgorithm(pubKey crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	// set the signature algorithm based on privatekey generated.
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return x509.SHA384WithRSA, nil
	case *ecdsa.PublicKey:
		bitLen := key.Curve.Params().BitSize
		switch bitLen {
		case 384:
			return x509.ECDSAWithSHA384, nil
		case 521, 512:
			return x509.ECDSAWithSHA512, nil
			// we should not really get into the 256 case as long as Generate keypair only support ecdsa keylength of 384 or 512.
			// just in case
		case 256:
			return x509.ECDSAWithSHA256, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("upsupported signature algorithm for certificate with ecdsa keys. only sha 384, 512 supported")

		}
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported public key type when generating certificate request. Only rsa and ecdsa supported")
	}
}

// CreateKeyPairAndCertificateRequest taken in parameters for certificate request and return der bytes for the CSR
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificateRequest(subject pkix.Name, hostList, keyType string, keyLength int) (certReq []byte, pkcs8Der []byte, err error) {

	//first let us look at type of keypair that we are generating
	privKey, pubKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   subject.CommonName,
			Organization: subject.Organization,
			Country:      subject.Country,
			Province:     subject.Province,
			Locality:     subject.Locality,
		},
	}
	template.SignatureAlgorithm, err = GetSignatureAlgorithm(pubKey)
	if err != nil {
		return nil, nil, err
	}

	hosts := strings.Split(hostList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certReq, err = x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate request. error : %s", err)
	}
	pkcs8Der, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return certReq, pkcs8Der, nil
}

// CreateKeyPairAndCertificate takes in parameters for certificate and return der bytes for the certificate
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificate(subject, hostList, keyType string, keyLength int) ([]byte, []byte, error) {

	//first let us look at type of keypair that we are generating
	privKey, pubKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
	}

	// generate self signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(8760 * time.Hour) // 1 year
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subject},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	template.SignatureAlgorithm, err = GetSignatureAlgorithm(pubKey)
	if err != nil {
		return nil, nil, err
	}

	hosts := strings.Split(hostList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate. error : %s", err)
	}
	pkcs8Der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return cert, pkcs8Der, nil
}

// GetPublicKeyFromCert retrieve the public key from a certificate
// We only support ECDSA and RSA public key
func GetPublicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as RSA cert does not match RSA public key struct")
	case x509.ECDSA:
		if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as ECDSA cert does not match ECDSA public key struct")
	}
	return nil, fmt.Errorf("only RSA and ECDSA public keys are supported")
}

// GetPublicKeyFromCertPem retrieve the public key from a certificate pem block
// We only support ECDSA and RSA public key
func GetPublicKeyFromCertPem(certPem []byte) (crypto.PublicKey, error) {
	cert, err := GetCertFromPem(certPem)
	if err != nil {
		return "", err
	}
	return GetPublicKeyFromCert(cert)
}

// GetPrivateKeyFromPem retrieve the private key from a private pem block
func GetPrivateKeyFromPem(keyPem []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: " + err.Error())
	}
	return key, nil
}

// GetPublicKeyFromPem retrieve the public key from a public pem block
func GetPublicKeyFromPem(keyPem []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: " + err.Error())
	}
	return key, nil
}

func GetCertFromPem(certPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

func GetCertAndChainFromPem(certPem []byte) (cert *x509.Certificate, chain *x509.CertPool, err error) {

	block, rest := pem.Decode(certPem)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}

	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}

	if chain = x509.NewCertPool(); chain.AppendCertsFromPEM(rest) {
		return
	}
	return cert, nil, nil
}

func GetCertFromPemFile(path string) (*x509.Certificate, error) {
	certPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read from certificate file %s : ", path)
	}
	return GetCertFromPem(certPem)
}

func GetSubjectCertsMapFromPemFile(path string) ([]x509.Certificate, error) {
	log.Debugf("crypt/x509:GetSubjectCertsMapFromPemFile() Loading certificates from  %s", path)

	certsBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return GetX509CertsFromPem(certsBytes)
}

func GetX509CertsFromPem(certBytes []byte) ([]x509.Certificate, error) {

	var certificates []x509.Certificate
	block, rest := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode pem bytes")
	}
	certAuth, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).Warn("crypt/x509:GetSubjectCertsMapFromPemFile() Failed to parse certificate")
	} else {
		certificates = append(certificates, *certAuth)
		log.Debugf("crypt/x509:GetSubjectCertsMapFromPemFile() CommonName %s", certAuth.Subject.CommonName)
	}

	// Return if no more certificates present in path file
	if rest == nil {
		return certificates, nil
	}

	for len(rest) > 1 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certAuth, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).Warn("crypt/x509:GetSubjectCertsMapFromPemFile() Failed to parse certificate")
			continue
		}
		certificates = append(certificates, *certAuth)
		log.Debugf("crypt/x509:GetSubjectCertsMapFromPemFile() CommonName %s", certAuth.Subject.CommonName)
	}
	return certificates, nil
}

// GetCertHashInHex returns hash of a certificate from a Pem block
func GetCertHashInHex(cert *x509.Certificate, hashAlg crypto.Hash) (string, error) {
	hash, err := GetHashData(cert.Raw, hashAlg)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash), nil
}

// GetCertHashFromPemInHex returns hash of a certificate from a Pem block
func GetCertHashFromPemInHex(certPem []byte, hashAlg crypto.Hash) (string, error) {
	cert, err := GetCertFromPem(certPem)
	if err != nil {
		return "", err
	}
	return GetCertHashInHex(cert, hashAlg)
}

func SavePrivateKeyAsPKCS8(keyDer []byte, filePath string) error {

	// marshal private key to disk
	keyOut, err := cos.OpenFileSafe(filePath, "", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	// Update private key readable to user and group only
	err = os.Chmod(filePath, 0640)
	if err != nil {
		return errors.Wrapf(err, "crypt/x509:SavePrivateKeyAsPKCS8() Error while changing file permission for file : %s", filePath)
	}
	defer func() {
		derr := keyOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}
	return nil

}

func GetPKCS8PrivKeyDerFromFile(path string) ([]byte, error) {

	privKeyPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read from private key file %s : ", path)
	}

	block, _ := pem.Decode(privKeyPem)
	if block == nil || block.Type != "PKCS8 PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to parse private Key PEM file")
	}

	return block.Bytes, nil
}

func GetPrivateKeyFromPKCS8File(path string) (interface{}, error) {
	privKeyDer, err := GetPKCS8PrivKeyDerFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not get private key from file - err: %v", err)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privKeyDer)
	if err != nil {
		return nil, fmt.Errorf("could not parse PKCS8 private key - err: %v", err)
	}
	return privKey, nil

}

func LoadX509CertAndPrivateKey(cp, kp string) (*x509.Certificate, interface{}, error) {
	cert, err := GetCertFromPemFile(cp)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load certificate. err: %v", err)
	}
	key, err := GetPrivateKeyFromPKCS8File(kp)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load private key. err: %v", err)
	}
	return cert, key, nil

}

func SavePemCertWithShortSha1FileName(certPem []byte, dir string) error {
	sha1Hex, err := GetCertHashFromPemInHex(certPem, crypto.SHA1)
	if err != nil {
		return fmt.Errorf("could not save certificate file with short sha1 file name. error %v", err)
	}
	// open file with restricted permissions
	filePath := filepath.Join(dir, sha1Hex[:9]+".pem")
	certOut, err := cos.OpenFileSafe(filePath, "", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open file for saving certificate with short sha1 filename - error :: %v", err)
	}
	defer func() {
		derr := certOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	err = os.Chmod(filePath, 0600)
	if err != nil {
		return fmt.Errorf("could not change file permissions: %s", filePath)
	}

	// let us decode and encode the block.. this is to make sure that there
	// is no junk data.. specially if it is a certificate chain.. also, we want to standardize
	// the header

	for block, rest := pem.Decode(certPem); block != nil && block.Type == "CERTIFICATE"; block, rest = pem.Decode(rest) {
		err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		if err != nil {
			return fmt.Errorf("could not encode certificate")
		}
	}

	return nil
}

func SavePemCert(cert []byte, certFilePath string) (err error) {
	certOut, err := cos.OpenFileSafe(certFilePath, "", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open file for writing: %v", err)
	}
	defer func() {
		derr := certOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	err = os.Chmod(certFilePath, 0600)
	if err != nil {
		return fmt.Errorf("could not change file permissions: %s", certFilePath)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return fmt.Errorf("could not pem encode cert: %v", err)
	}

	return nil
}

func SavePemCertChain(certFilePath string, certs ...[]byte) error {
	certOut, err := cos.OpenFileSafe(certFilePath, "", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open file for writing: %v", err)
	}
	defer func() {
		derr := certOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	err = os.Chmod(certFilePath, 0640)
	if err != nil {
		return fmt.Errorf("could not change file permissions: %s", certFilePath)
	}

	for _, cert := range certs {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("could not pem encode cert: %v", err)
		}
	}
	return nil
}

func GetCertPool(certs []x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for i := range certs {
		certPool.AddCert(&certs[i])
	}
	return certPool
}

func GetCertsFromDir(path string) ([]x509.Certificate, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, errors.Wrap(err, "Error while reading certs from dir"+path)
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	var certificates []x509.Certificate
	for _, certFile := range files {
		certFilePath := path + certFile.Name()
		certs, err := GetSubjectCertsMapFromPemFile(certFilePath)
		if err != nil {
			log.WithError(err).Warn("Error while reading certs from dir - " + certFilePath)
		}

		for _, v := range certs {
			certificates = append(certificates, v)
		}
	}
	return certificates, nil
}

// GetCertificate gets the Certificate from PEM
func GetCertificate(signingCertPems interface{}) ([][]byte, error) {

	var certPemSlice [][]byte

	switch signingCertPems.(type) {
	case [][]byte:
		certPemSlice = signingCertPems.([][]byte)
	case []byte:
		certPemSlice = [][]byte{signingCertPems.([]byte)}
	default:
		return nil, errors.New("signingCertPems has to be of type []byte or [][]byte")

	}
	return certPemSlice, nil
}

func GetCertExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, ext := range cert.Extensions {
		if reflect.DeepEqual(ext.Id, oid) {
			return ext.Value
		}
	}
	return nil
}

func GetLeafCert(certchain []*x509.Certificate) *x509.Certificate {
	var cert *x509.Certificate
	for _, cert = range certchain {
		if !cert.IsCA {
			break
		}
	}
	return cert
}

// VerifyEKCertChain verifies a cert chain for validity and ensures no certs have been
// revoked
func VerifyEKCertChain(enableRevokeCheck bool, ekCertChain []*x509.Certificate, ecPool *x509.CertPool) error {
	if ekCertChain == nil {
		return errors.New("crypt/x509/VerifyEKCertChain: cert chain is empty")
	}

	var roots *x509.CertPool
	if ecPool == nil {
		roots = x509.NewCertPool()
	} else {
		roots = ecPool
	}
	inters := x509.NewCertPool()
	var lc *x509.Certificate

	// split into root and intermediate CAs
	for _, cert := range ekCertChain {
		if cert.IsCA {
			// root certs have issuer == subject
			if cert.Subject.String() == cert.Issuer.String() {
				roots.AddCert(cert)
				continue
			} else {
				// intermediate certs have distinct issuers and subjects
				inters.AddCert(cert)
				continue
			}
		} else {
			// leaf cert
			lc = cert
		}
	}

	// set params for verification
	vopts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// verify leaf cert
	validExtKeyUsage := false

	if lc == nil {
		return errors.Errorf("crypt/x509/VerifyEKCertChain: leaf cert is missing from chain")
	}

	// check if the leaf cert has extended key usage 2.23.133.8.1 required for TPM EK Certs
	// http://oid-info.com/get/2.23.133.8.1
	for _, eku := range lc.UnknownExtKeyUsage {
		if strings.Contains(eku.String(), "2.23.133.8.1") {
			validExtKeyUsage = true
			break
		}
	}
	if !validExtKeyUsage {
		return errors.Errorf("crypt/x509/VerifyEKCertChain: cert %v "+
			"EK cert key usage is not valid", lc.Subject.CommonName)
	}

	removeCritExt := false
	// TPM EK Certs contain critical extensions like 2.5.29.17 which cannot be handled by Go's x509 package
	// these need to be removed before the verification process
	if len(lc.UnhandledCriticalExtensions) > 0 {
		for _, uhce := range lc.UnhandledCriticalExtensions {
			if strings.Contains(uhce.String(), "2.5.29.17") {
				removeCritExt = true
				break
			}
		}
	}
	if removeCritExt {
		// strip unhandled critical extensions list
		// go x509 does not support these since this will cause Verify to fail
		lc.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	}
	_, err := lc.Verify(vopts)
	if err != nil {
		return errors.Wrapf(err, "crypt/x509/VerifyEKCertChain: cert %v "+
			"failed verification", lc.Subject)
	}
	if enableRevokeCheck {
		for _, cert := range ekCertChain {
			isRevoked, isOk, err := revoke.VerifyCertificateError(cert)
			if err != nil || !isOk {
				return errors.Errorf("crypt/x509/VerifyEKCertChain: revocation check failed for cert %v", cert.Subject)
			}
			if isOk && isRevoked {
				return errors.Errorf("crypt/x509/VerifyEKCertChain: cert %v was revoked", cert.Subject)
			}
		}
	}

	return nil
}
