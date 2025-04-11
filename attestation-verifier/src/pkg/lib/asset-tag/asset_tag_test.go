/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package asset_tag

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"math/big"
	"testing"
	"time"

	hc "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/stretchr/testify/assert"
)

// unit test suit to test out the CreateAssetTag() function
func TestAtag_CreateAssetTag(t *testing.T) {
	privKey, cert, err := createX509CertAndKey()
	if err != nil {
		t.Fatalf("Error generating the key and certificate : %v", err)
	}

	tagConfig := hvs.TagCertConfig{
		SubjectUUID: "803f6068-06da-e811-906e-00163566263e",
		PrivateKey:  privKey,
		TagCACert:   cert,
		TagAttributes: []hvs.TagKvAttribute{{
			Key:   "Country",
			Value: "US",
		}, {
			Key:   "Country",
			Value: "India",
		}},
		ValidityInSeconds: 1000,
	}

	newTag := NewAssetTag()
	tagCertificate, err := newTag.CreateAssetTag(tagConfig)
	if err != nil {
		t.Fatalf("Error while creating an asset tag: %v", err)
	}
	assert.NotNil(t, tagCertificate)

	// validating the created asset tag
	parsedCert, err := x509.ParseCertificate(tagCertificate)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	assert.Equal(t, "CN=803f6068-06da-e811-906e-00163566263e", parsedCert.Subject.String())
	assert.Equal(t, "CN=HVS Tag Certificate", parsedCert.Issuer.String())

	// validate tag key-value attributes
	for _, extensions := range parsedCert.Extensions {
		var tagAttr hvs.TagKvAttribute
		_, err = asn1.Unmarshal(extensions.Value, &tagAttr)
		assert.NoError(t, err)
		assert.Equal(t, "Country", tagAttr.Key)
		assert.Contains(t, "US India", tagAttr.Value)
	}

	// invalid subject UUID test
	tagConfig = hvs.TagCertConfig{
		SubjectUUID: "",
		PrivateKey:  privKey,
		TagCACert:   cert,
		TagAttributes: []hvs.TagKvAttribute{{
			Key:   "Country",
			Value: "US",
		}, {
			Key:   "Country",
			Value: "India",
		}},
		ValidityInSeconds: 1000,
	}

	_, err = newTag.CreateAssetTag(tagConfig)
	assert.EqualError(t, errors.New("Subject UUID is required to be set to create an asset tag certificate"), err.Error())

	// invalid tag-attributes test
	tagConfig = hvs.TagCertConfig{
		SubjectUUID:       "803f6068-06da-e811-906e-00163566263e",
		PrivateKey:        privKey,
		TagCACert:         cert,
		TagAttributes:     []hvs.TagKvAttribute{},
		ValidityInSeconds: 1000,
	}

	_, err = newTag.CreateAssetTag(tagConfig)
	assert.EqualError(t, errors.New("Tag key-value attributes are required to be set to create an asset tag certificate"), err.Error())

	// invalid validity test
	tagConfig = hvs.TagCertConfig{
		SubjectUUID: "803f6068-06da-e811-906e-00163566263e",
		PrivateKey:  privKey,
		TagCACert:   cert,
		TagAttributes: []hvs.TagKvAttribute{{
			Key:   "Country",
			Value: "US",
		}, {
			Key:   "Country",
			Value: "India",
		}},
		ValidityInSeconds: 0,
	}

	_, err = newTag.CreateAssetTag(tagConfig)
	assert.EqualError(t, errors.New("Certificate validity in seconds required to be set to create an asset tag certificate"), err.Error())

	// invalid private key test
	var key *rsa.PrivateKey
	tagConfig = hvs.TagCertConfig{
		SubjectUUID: "803f6068-06da-e811-906e-00163566263e",
		PrivateKey:  key,
		TagCACert:   cert,
		TagAttributes: []hvs.TagKvAttribute{{
			Key:   "Country",
			Value: "US",
		}, {
			Key:   "Country",
			Value: "India",
		}},
		ValidityInSeconds: 1000,
	}

	_, err = newTag.CreateAssetTag(tagConfig)
	assert.EqualError(t, errors.New("Private key is required to be set to create an asset tag certificate"), err.Error())

	// invalid tag-ca cert test
	var tagCaCert x509.Certificate
	tagConfig = hvs.TagCertConfig{
		SubjectUUID: "803f6068-06da-e811-906e-00163566263e",
		PrivateKey:  privKey,
		TagCACert:   &tagCaCert,
		TagAttributes: []hvs.TagKvAttribute{{
			Key:   "Country",
			Value: "US",
		}, {
			Key:   "Country",
			Value: "India",
		}},
		ValidityInSeconds: 1000,
	}

	_, err = newTag.CreateAssetTag(tagConfig)
	assert.EqualError(t, errors.New("Tag CA-Certificate is required to be set to fetch issuer configuration information to create an asset tag certificate"), err.Error())

}

func TestAtag_DeployAssetTag(t *testing.T) {
	newTag := NewAssetTag()
	var trustedCAcerts []x509.Certificate
	htcFactory := hc.NewHostConnectorFactory("", trustedCAcerts, nil, false)
	connector, err := htcFactory.NewHostConnector("https://ta.ip.com:1443;u=serviceUsername;p=servicePassword")
	assert.NoError(t, err)
	dtErr := newTag.DeployAssetTag(connector, "0966d97d182ee8fac40bee16018e762ae46a026f0bb437600e029a755f8745a9a6bb8b3da152ea37ef52f0d855b6622f\n", "803f6068-06da-e811-906e-00163566263e")
	assert.NotNil(t, dtErr)
	dtErrNew := newTag.DeployAssetTag(connector, "", "")
	assert.NotNil(t, dtErrNew)
}

// createX509CertAndKey() method id used to create an certificate and a RSA private key
func createX509CertAndKey() (*rsa.PrivateKey, *x509.Certificate, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(0),
		NotBefore:          now.Add(-5 * time.Minute),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{},
		SignatureAlgorithm: x509.SHA384WithRSA,
		Issuer: pkix.Name{
			CommonName: "HVS CA",
		},
		Subject: pkix.Name{
			CommonName: "HVS Tag Certificate",
		},
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &privkey.PublicKey, privkey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, err
	}
	return privkey, certificate, nil
}
