/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto"
	"crypto/x509"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/pkg/errors"
	"strings"
)

var defaultLog = log.GetDefaultLogger()

type CaCertTypes string

func (cct CaCertTypes) String() string {
	return string(cct)
}

const (
	CaCertTypesRootCa        CaCertTypes = "root"
	CaCertTypesEndorsementCa CaCertTypes = "endorsement"
)

// CertificatesStore reads and caches map of certificate type and CertificateStore in application
type CertificatesStore map[string]*CertificateStore

// CertificateStore holds file/directory path and certificates collection
type CertificateStore struct {
	Key          crypto.PrivateKey
	CertPath     string
	Certificates []x509.Certificate
}

// CertificatesPathStore
type CertificatesPathStore map[string]CertLocation //map of certificate type and associated locations

type CertLocation struct {
	KeyFile  string
	CertPath string // Can hold either certFile or certDir
}

func (cs *CertificatesStore) GetPath(certType string) string {
	certStore := (*cs)[certType]
	return certStore.CertPath
}
func LoadCertificates(certificatePaths *CertificatesPathStore, certType []string) (*CertificatesStore, error) {
	defaultLog.Trace("crypt/certificate_store:LoadCertificates() Entering")
	defer defaultLog.Trace("crypt/certificate_store:LoadCertificates() Leaving")

	certificateStore := make(CertificatesStore)
	var err error
	for _, certType := range certType {
		certloc := (*certificatePaths)[certType]
		if certType == CaCertTypesRootCa.String() || certType == CaCertTypesEndorsementCa.String() {
			certificateStore[certType] = loadCertificatesFromDir(&certloc)
		} else {
			certificateStore[certType], err = loadCertificatesFromFile(&certloc)
			if err != nil {
				return &certificateStore, errors.Wrap(err, "cry"+
					"pt/certificate_store:LoadCertificates() Could not load certificate from file - "+certloc.CertPath)
			}
		}
	}
	defaultLog.Debug("crypt/certificate_store:LoadCertificates() Loaded certificates")
	for _, certType := range certType {
		defaultLog.Debugf("crypt/certificate_store:LoadCertificates() Certificates loaded for type - %s", certType)
		certStore := certificateStore[certType]
		if certStore != nil && certStore.Certificates != nil {
			for _, cert := range certStore.Certificates {
				defaultLog.Debugf("crypt/certificate_store:LoadCertificates() Certificate CN - %s", cert.Subject.CommonName)
			}
		}
	}
	return &certificateStore, nil
}

func loadCertificatesFromFile(certLocation *CertLocation) (*CertificateStore, error) {
	defaultLog.Trace("crypt/certificate_store:loadCertificatesFromFile() Entering")
	defer defaultLog.Trace("crypt/certificate_store:loadCertificatesFromFile() Leaving")

	key := loadKey(certLocation.KeyFile)
	certs, err := GetSubjectCertsMapFromPemFile(certLocation.CertPath)
	if err != nil {
		return &CertificateStore{
			Key:          key,
			CertPath:     certLocation.CertPath,
			Certificates: certs,
		}, errors.Wrapf(err, "crypt/certificate_store:loadCertificatesFromFile() Error while reading certs from file - "+certLocation.CertPath)
	}

	return &CertificateStore{
		Key:          key,
		CertPath:     certLocation.CertPath,
		Certificates: certs,
	}, nil
}

func loadCertificatesFromDir(certLocation *CertLocation) *CertificateStore {
	defaultLog.Trace("crypt/certificate_store:loadCertificatesFromDir() Entering")
	defer defaultLog.Trace("crypt/certificate_store:loadCertificatesFromDir() Leaving")

	certificates, err := GetCertsFromDir(certLocation.CertPath)
	if err != nil {
		defaultLog.WithError(err).Warnf("crypt/certificate_store:loadCertificatesFromDir() Error while reading certificates from " + certLocation.CertPath)
	}
	key := loadKey(certLocation.KeyFile)
	return &CertificateStore{
		Key:          key,
		CertPath:     certLocation.CertPath,
		Certificates: certificates,
	}
}

func loadKey(keyFile string) crypto.PrivateKey {
	defaultLog.Trace("crypt/certificate_store:loadKey() Entering")
	defer defaultLog.Trace("crypt/certificate_store:loadKey() Leaving")

	if keyFile == "" {
		return nil
	}
	key, err := GetPrivateKeyFromPKCS8File(keyFile)
	if err != nil {
		defaultLog.WithError(err).Errorf("crypt/certificate_store:loadKey() Error while reading key from file - " + keyFile)
	}
	return key
}

func (cs *CertificatesStore) AddCertificatesToStore(certType, certFile string, certificate *x509.Certificate) error {
	defaultLog.Trace("crypt/certificate_store:AddCertificatesToStore() Entering")
	defer defaultLog.Trace("crypt/certificate_store:AddCertificatesToStore() Leaving")

	certStore := (*cs)[certType]
	// Save certificate to file with common name
	certPath := certStore.CertPath + strings.Replace(certFile, " ", "", -1) + ".pem"
	err := SavePemCert(certificate.Raw, certPath)
	if err != nil {
		return errors.Errorf("Failed to store certificate %s", certPath)
	}

	// Add certificate to store
	certStore.Certificates = append(certStore.Certificates, *certificate)

	return nil
}

func (cs *CertificatesStore) GetKeyAndCertificates(certType string) (crypto.PrivateKey, []x509.Certificate, error) {
	defaultLog.Trace("crypt/certificate_store:GetKeyAndCertificates() Entering")
	defer defaultLog.Trace("crypt/certificate_store:GetKeyAndCertificates() Leaving")

	certStore := (*cs)[certType]
	if certStore != nil {
		return certStore.Key, certStore.Certificates, nil
	}
	return nil, nil, errors.Errorf("Certificate store is empty for certType: %s", certType)
}

// This function expects CN to be unique, use this only in that scenario
func (cs *CertificatesStore) RetrieveCertificate(certType, commonName string) (*x509.Certificate, error) {
	defaultLog.Trace("crypt/certificate_store:RetrieveCertificate() Entering")
	defer defaultLog.Trace("crypt/certificate_store:RetrieveCertificate() Leaving")

	certStore := (*cs)[certType]
	if certStore != nil {
		for _, cert := range certStore.Certificates {
			if cert.Issuer.CommonName == strings.ReplaceAll(commonName, "\\x00", "") {
				return &cert, nil
			}
		}
	}
	return nil, nil
}
