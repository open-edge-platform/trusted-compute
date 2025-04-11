/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package asset_tag

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	hc "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"math/big"
	"reflect"
	"time"
)

type atag struct {
}

// CreateAssetTag implements the interface AssetTag to create an asset tag certificate for a particular host with custom tag attributes
func (aTag *atag) CreateAssetTag(tagCertConfig hvs.TagCertConfig) ([]byte, error) {
	err := validateTagCertConfig(tagCertConfig)
	if err != nil {
		return nil, err
	}

	_, err = x509.ParseCertificate(tagCertConfig.TagCACert.Raw)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse the certificate to create an asset tag certificate")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate serial number")
	}

	var extensions []pkix.Extension

	for _, tagKvAttribute := range tagCertConfig.TagAttributes {
		derEncodedAttr, err := asn1.Marshal(tagKvAttribute)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to marshal ASN1 Tag Cert attributes")
		}
		extensions = append(extensions, pkix.Extension{
			Critical: false,
			Id:       asn1.ObjectIdentifier{2, 5, 4, 789, 1},
			Value:    derEncodedAttr,
		})
	}

	certConfig := hvs.TagCertBuilderConfig{
		TagCertConfig:    tagCertConfig,
		SerialNumber:     serialNumber,
		ValidityDuration: time.Duration(tagCertConfig.ValidityInSeconds) * time.Second,
		SubjectName: pkix.Name{
			CommonName: tagCertConfig.SubjectUUID,
		},
		Extensions: extensions,
	}

	return tagCertificateBuilder(certConfig)
}

func tagCertificateBuilder(certConfig hvs.TagCertBuilderConfig) ([]byte, error) {

	if certConfig.SerialNumber == nil || certConfig.SubjectName.CommonName == "" || certConfig.TagCertConfig.TagCACert == nil ||
		certConfig.Extensions == nil || certConfig.ValidityDuration.Seconds() < 0 {
		return nil, errors.New("Missing certificate attributes to create asset tag certificate")
	}

	certificateTemplate := &x509.Certificate{
		SerialNumber:       certConfig.SerialNumber,
		Issuer:             certConfig.TagCertConfig.TagCACert.Issuer,
		Subject:            certConfig.SubjectName,
		ExtraExtensions:    certConfig.Extensions,
		SignatureAlgorithm: x509.SHA384WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(certConfig.ValidityDuration),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certConfig.TagCertConfig.TagCACert, certConfig.TagCertConfig.TagCACert.PublicKey, certConfig.TagCertConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Error while creating asset tag certificate: %s", err)
	}

	return derBytes, nil
}

// DeployAssetTag implements the interface AssetTag to deploy an asset tag certificate on a particular host with custom tag attributes
func (aTag *atag) DeployAssetTag(connector hc.HostConnector, tagCertDigest, hostHardwareUUID string) error {

	if tagCertDigest == "" || hostHardwareUUID == "" {
		return errors.New("Invalid input: tag sha384 digest and host hardware UUID must be given to deploy an asset tag")
	}

	err := connector.DeployAssetTag(hostHardwareUUID, tagCertDigest)
	if err != nil {
		return fmt.Errorf("Error while deploying asset tag certificate on host %s: %s", hostHardwareUUID, err)
	}
	return nil
}

// validateTagCertConfig function is used to validate the CreateAssetTag input
func validateTagCertConfig(tagCertConfig hvs.TagCertConfig) error {
	if tagCertConfig.TagCACert == nil || tagCertConfig.TagCACert.Raw == nil {
		return errors.New("Tag CA-Certificate is required to be set to fetch issuer configuration information to create an asset tag certificate")
	}
	if tagCertConfig.SubjectUUID == "" {
		return errors.New("Subject UUID is required to be set to create an asset tag certificate")
	}
	if tagCertConfig.ValidityInSeconds <= 0 {
		return errors.New("Certificate validity in seconds required to be set to create an asset tag certificate")
	}
	if tagCertConfig.PrivateKey == nil || reflect.ValueOf(tagCertConfig.PrivateKey).IsNil() {
		return errors.New("Private key is required to be set to create an asset tag certificate")
	}
	if tagCertConfig.TagAttributes == nil || len(tagCertConfig.TagAttributes) <= 0 {
		return errors.New("Tag key-value attributes are required to be set to create an asset tag certificate")
	}
	return nil
}
