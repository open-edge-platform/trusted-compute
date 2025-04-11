/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"bytes"
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

type ReportsClient interface {
	CreateSAMLReport(hvs.ReportCreateRequest) ([]byte, error)
	CreateReportAsync(hvs.ReportCreateRequest) (error, *http.Response)
}

type reportsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client reportsClientImpl) CreateSAMLReport(reportCreateRequest hvs.ReportCreateRequest) ([]byte, error) {
	log.Trace("hvsclient/reports_client:CreateSAMLReport() Entering")
	defer log.Trace("hvsclient/reports_client:CreateSAMLReport() Leaving")

	jsonData, err := json.Marshal(reportCreateRequest)
	if err != nil {
		return nil, err
	}

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Configured HVS URL is malformed")
	}
	reports, _ := parsedUrl.Parse("reports")
	endpoint := parsedUrl.ResolveReference(reports)
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Failed to instantiate http request to HVS")
	}

	req.Header.Set("Accept", "application/samlassertion+xml")
	req.Header.Set("Content-Type", "application/json")

	var samlReport []byte
	if client.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
		rsp, err := client.httpClient.Do(req)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while sending request from client to server")
			log.Tracef("%+v", err)
			return nil, err
		}
		samlReport, err = ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while reading response body")
			return nil, err
		}
	} else {
		certs, err := crypt.GetCertsFromDir(client.cfg.CaCertsDir)
		if err != nil {
			return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Error while retrieving ca certs from dir")
		}
		samlReport, err = util.SendRequest(req, client.cfg.AasAPIUrl, client.cfg.UserName, client.cfg.Password, certs)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while sending request")
			return nil, err
		}
	}

	// now validate SAML
	err = validation.ValidateXMLString(string(samlReport))
	if err != nil {
		return nil, err
	}

	return samlReport, nil
}

func (client reportsClientImpl) CreateReportAsync(reportCreateRequest hvs.ReportCreateRequest) (error, *http.Response) {
	log.Trace("hvsclient/reports_client:CreateReportAsync() Entering")
	defer log.Trace("hvsclient/reports_client:CreateReportAsync() Leaving")

	jsonData, err := json.Marshal(reportCreateRequest)
	if err != nil {
		return err, nil
	}

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return errors.Wrap(err, "hvsclient/reports_client:CreateReportAsync() Configured HVS URL is malformed"), nil
	}
	if client.cfg.BearerToken == "" {
		return errors.Wrap(err, "hvsclient/reports_client:CreateReportAsync() BEARER_TOKEN is not set"), nil
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "reports")
	queryString := parsedUrl.Query()
	queryString.Set("process", "async")
	parsedUrl.RawQuery = queryString.Encode()
	endpoint := parsedUrl.ResolveReference(parsedUrl)

	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return errors.Wrap(err, "hvsclient/reports_client:CreateReportAsync() Failed to instantiate http request to HVS"), nil
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

	rsp, err := client.httpClient.Do(req)
	if err != nil {
		log.Error("hvsclient/reports_client:CreateReportAsync() Error while sending request from client to server")
		log.Tracef("%+v", err)
		return err, rsp
	}
	return nil, rsp
}
