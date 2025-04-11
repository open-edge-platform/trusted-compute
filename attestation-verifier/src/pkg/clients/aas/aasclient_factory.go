/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

// AasClientProvider returns an AasClient
type AasClientProvider interface {
	GetAasClient() (Client, error)
}

type DefaultAasClientProvider struct {
	AasUrl, BearerToken, CaCertsDir string
}

// GetAasClient returns a standard AAS client
func (aasCp DefaultAasClientProvider) GetAasClient() (Client, error) {

	if err := validation.ValidateJWT(aasCp.BearerToken); err != nil {
		return Client{}, errors.Wrap(err, "invalid bearer token")
	}

	// validate AAS URL
	if err := validation.ValidateURL(aasCp.AasUrl, map[string]byte{"http": 0, "https": 0}, "/aas/v1/"); err != nil {
		return Client{}, errors.Wrap(err, "invalid AAS base URL")
	}

	// validate CA certs dir
	caCerts, err := crypt.GetCertsFromDir(aasCp.CaCertsDir)
	if err != nil {
		return Client{}, errors.Wrapf(err, "failed to read certs from %s", aasCp.CaCertsDir)
	}

	// init client
	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		return Client{}, errors.Wrap(err, " creating http client")
	}

	return Client{
		BaseURL:    aasCp.AasUrl,
		JWTToken:   []byte(aasCp.BearerToken),
		HTTPClient: client,
	}, nil
}
