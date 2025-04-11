/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

var privacyCAInstance *rsa.PublicKey

// GetPrivacyCA utility function returns the privacy-ca key stored at
// /opt/trustagent/configuration/privacy-ca.cer.  It assumes the file has been
// created by 'tagent setup' (in tasks.download_privacy_ca.go) and returns an error
// if the file does not exist.
func GetPrivacyCA(privacyCA string) (*rsa.PublicKey, error) {
	log.Trace("util/privacy_ca:GetPrivacyCA() Entering")
	defer log.Trace("util/privacy_ca:GetPrivacyCA() Leaving")

	if privacyCAInstance == nil {
		if _, err := os.Stat(privacyCA); os.IsNotExist(err) {
			return nil, errors.Wrapf(err, "File %s does not exist", privacyCA)
		}

		privacyCaBytes, err := ioutil.ReadFile(privacyCA)
		if err != nil {
			return nil, errors.Wrap(err, "util/privacy_ca:GetPrivacyCA() Error while reading Privacy CA Certificate file")
		}

		cert, err := x509.ParseCertificate(privacyCaBytes)
		if err != nil {
			return nil, errors.Wrap(err, "util/privacy_ca:GetPrivacyCA() Error while parsing Privacy CA Certificate")
		}

		privacyCAInstance = cert.PublicKey.(*rsa.PublicKey)
	}

	return privacyCAInstance, nil
}
