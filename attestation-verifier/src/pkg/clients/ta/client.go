/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ta

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/util"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type TAClient interface {
	GetHostInfo() (taModel.HostInfo, error)
	GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error)
	GetAIK() ([]byte, error)
	GetBindingKeyCertificate() ([]byte, error)
	DeployAssetTag(hardwareUUID, tag string) error
	DeploySoftwareManifest(manifest taModel.Manifest) error
	GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error)
	GetBaseURL() *url.URL
}

func NewTAClient(aasApiUrl string, taApiUrl *url.URL, serviceUserName, serviceUserPassword string,
	trustedCaCerts []x509.Certificate, imaMeasureEnabled bool) (TAClient, error) {

	taClient := taClient{
		AasURL:            aasApiUrl,
		BaseURL:           taApiUrl,
		ServiceUsername:   serviceUserName,
		ServicePassword:   serviceUserPassword,
		TrustedCaCerts:    trustedCaCerts,
		ImaMeasureEnabled: imaMeasureEnabled,
	}

	return &taClient, nil
}

type taClient struct {
	AasURL            string
	BaseURL           *url.URL
	ServiceUsername   string
	ServicePassword   string
	TrustedCaCerts    []x509.Certificate
	ImaMeasureEnabled bool
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (tc *taClient) GetHostInfo() (taModel.HostInfo, error) {
	log.Trace("clients/trust_agent_client:GetHostInfo() Entering")
	defer log.Trace("clients/trust_agent_client:GetHostInfo() Leaving")

	var hostInfo taModel.HostInfo

	requestURL, err := url.Parse(tc.BaseURL.String() + "/host")
	if err != nil {
		return hostInfo, errors.New("client/trust_agent_client:GetHostInfo() error forming GET host info URL")
	}
	log.Debug("client/trust_agent_client:GetHostInfo() Request URL created for host info")
	httpRequest, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return hostInfo, err
	}

	log.Debugf("clients/trust_agent_client:GetHostInfo() TA host info retrieval GET request URL: %s", requestURL.String())
	httpRequest.Header.Set("Accept", "application/json")

	httpResponse, err := util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return hostInfo, errors.Wrap(err, "client/trust_agent_client:GetHostInfo() Error while getting response"+
			" from Get host info from TA API")
	}
	err = json.Unmarshal(httpResponse, &hostInfo)
	if err != nil {
		return hostInfo, errors.Wrap(err, "client/trust_agent_client:GetHostInfo() Error while unmarshalling"+
			" response from Get host info from TA API")
	}
	log.Info("client/trust_agent_client:GetHostInfo() Successfully received host details from TA")
	return hostInfo, nil
}

func (tc *taClient) GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error) {
	log.Trace("clients/trust_agent_client:GetTPMQuote() Entering")
	defer log.Trace("clients/trust_agent_client:GetTPMQuote() Leaving")

	var quoteRequest taModel.TpmQuoteRequest
	var quoteResponse taModel.TpmQuoteResponse

	requestURL, err := url.Parse(tc.BaseURL.String() + "/tpm/quote")
	if err != nil {
		return quoteResponse, errors.New("client/trust_agent_client:GetTPMQuote() error forming GET host manifest URL")
	}
	log.Debug("client/trust_agent_client:GetTPMQuote() Request URL created for host manifest")
	quoteRequest.Nonce, err = base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return quoteResponse, errors.New("client/trust_agent_client:GetTPMQuote() Error decoding nonce from base64 to bytes")
	}
	quoteRequest.Pcrs = pcrList
	quoteRequest.PcrBanks = pcrBankList
	quoteRequest.ImaMeasureEnabled = tc.ImaMeasureEnabled

	secLog.Debug("client/trust_agent_client:GetTPMQuote() Successfully decoded nonce from base 64 to bytes")
	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(quoteRequest)
	secLog.Debugf("client/trust_agent_client:GetTPMQuote() TPM quote request: %s", buffer.String())
	httpRequest, err := http.NewRequest(http.MethodPost, requestURL.String(), buffer)
	if err != nil {
		return quoteResponse, err
	}

	log.Debugf("clients/trust_agent_client:GetTPMQuote() TA host manifest retrieval POST request URL: %s", requestURL.String())
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return quoteResponse, errors.Wrap(err, "client/trust_agent_client:GetTPMQuote() Error while getting response"+
			" from Get host manifest from TA API")
	}
	secLog.Debugf("client/trust_agent_client:GetTPMQuote() TPM quote response: %s", string(httpResponse))
	err = xml.Unmarshal(httpResponse, &quoteResponse)
	if err != nil {
		return quoteResponse, errors.Wrap(err, "client/trust_agent_client:GetTPMQuote() Error while unmarshalling"+
			" response from Get host manifest from TA API")
	}
	log.Info("client/trust_agent_client:GetTPMQuote() Successfully received TPM quote response from TA")
	return quoteResponse, nil
}

func (tc *taClient) GetAIK() ([]byte, error) {
	log.Trace("clients/trust_agent_client:GetAIK() Entering")
	defer log.Trace("clients/trust_agent_client:GetAIK() Leaving")

	requestURL, err := url.Parse(tc.BaseURL.String() + "/aik")
	if err != nil {
		return nil, errors.Wrap(err, "client/trust_agent_client:GetAIK() Error forming GET AIK certificate URL")
	}
	log.Debug("clients/trust_agent_client:GetAIK() Request URL created for AIK certificate")

	httpRequest, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("clients/trust_agent_client:GetAIK() TA AIK certificate retrieval GET request URL: %s", requestURL.String())

	httpResponse, err := util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "client/trust_agent_client:GetAIK() Error while getting response"+
			" from Get AIK API")
	}
	log.Info("clients/trust_agent_client:GetAIK() Successfully received AIK certificate from TA")
	return httpResponse, nil
}

func (tc *taClient) GetBindingKeyCertificate() ([]byte, error) {
	log.Trace("clients/trust_agent_client:GetBindingKeyCertificate() Entering")
	defer log.Trace("clients/trust_agent_client:GetBindingKeyCertificate() Leaving")

	requestURL, err := url.Parse(tc.BaseURL.String() + "/binding-key-certificate")
	if err != nil {
		return nil, errors.New("client/trust_agent_client:GetBindingKeyCertificate() Error forming GET binding key " +
			"certificate URL")
	}
	log.Debug("clients/trust_agent_client:GetBindingKeyCertificate() Request URL created for Binding Key certificate")
	httpRequest, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/x-pem-file")

	secLog.Debugf("clients/trust_agent_client:GetBindingKeyCertificate() TA Binding key certificate retrieval "+
		"GET request URL: %s", requestURL.String())

	httpResponse, err := util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "client/trust_agent_client:GetBindingKeyCertificate() Error while "+
			"getting response  from Get Binding key certificate API")
	}
	log.Info("clients/trust_agent_client:GetBindingKeyCertificate() Successfully received Binding key certificate from TA")
	return httpResponse, nil
}

func (tc *taClient) DeployAssetTag(hardwareUUID, tag string) error {
	log.Trace("clients/trust_agent_client:DeployAssetTag() Entering")
	defer log.Trace("clients/trust_agent_client:DeployAssetTag() Leaving")

	var tagWriteRequest taModel.TagWriteRequest

	requestURL, err := url.Parse(tc.BaseURL.String() + "/tag")
	if err != nil {
		return errors.New("client/trust_agent_client:DeployAssetTag() error forming deploy asset tag URL")
	}
	log.Debug("clients/trust_agent_client:GetBindingKeyCertificate() Request URL created for Deploying asset tag")
	tagWriteRequest.Tag, err = base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return errors.New("client/trust_agent_client:DeployAssetTag() Error decoding tag from base64 to bytes")
	}
	tagWriteRequest.HardwareUUID = hardwareUUID

	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(tagWriteRequest)
	secLog.Debugf("TAG request: %s", buffer.String())
	httpRequest, err := http.NewRequest(http.MethodPost, requestURL.String(), buffer)
	if err != nil {
		return err
	}

	log.Debugf("clients/trust_agent_client:DeployAssetTag() TA asset tag deploy POST request URL: %s", requestURL.String())
	httpRequest.Header.Set("Content-Type", "application/json")

	_, err = util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return errors.Wrap(err, "client/trust_agent_client:DeployAssetTag() Error while getting response"+
			" from Deploy asset tag from TA API")
	}
	log.Info("clients/trust_agent_client:GetAIK() Successfully deployed asset tag to host")
	return nil
}

func (tc *taClient) DeploySoftwareManifest(manifest taModel.Manifest) error {
	log.Trace("clients/trust_agent_client:DeploySoftwareManifest() Entering")
	defer log.Trace("clients/trust_agent_client:DeploySoftwareManifest() Leaving")

	requestURL, err := url.Parse(tc.BaseURL.String() + "/deploy/manifest")
	if err != nil {
		return errors.New("client/trust_agent_client:DeploySoftwareManifest() error forming deploy software manifest URL")
	}

	buffer := new(bytes.Buffer)
	err = xml.NewEncoder(buffer).Encode(manifest)
	log.Debugf("Manifest request: %s", buffer.String())
	httpRequest, err := http.NewRequest(http.MethodPost, requestURL.String(), buffer)
	if err != nil {
		return err
	}

	log.Debugf("clients/trust_agent_client:DeploySoftwareManifest() TA software manifest deploy POST request URL: %s", requestURL.String())
	httpRequest.Header.Set("Content-Type", "application/xml")

	_, err = util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return errors.Wrap(err, "client/trust_agent_client:DeploySoftwareManifest() Error while getting response"+
			" from Deploy software manifest from TA API")
	}
	log.Info("clients/trust_agent_client:DeploySoftwareManifest() Successfully deployed software manifest to host")
	return nil
}

func (tc *taClient) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	log.Trace("clients/trust_agent_client:GetMeasurementFromManifest() Entering")
	defer log.Trace("clients/trust_agent_client:GetMeasurementFromManifest() Leaving")

	var measurement taModel.Measurement
	requestURL, err := url.Parse(tc.BaseURL.String() + "/host/application-measurement")
	if err != nil {
		return measurement, errors.New("client/trust_agent_client:GetMeasurementFromManifest() error forming host application measurement URL")
	}

	buffer := new(bytes.Buffer)
	err = xml.NewEncoder(buffer).Encode(manifest)
	log.Debugf("Manifest request: %s", buffer.String())
	httpRequest, err := http.NewRequest(http.MethodPost, requestURL.String(), buffer)
	if err != nil {
		return measurement, err
	}

	log.Debugf("clients/trust_agent_client:GetMeasurementFromManifest() TA host application measurement POST request URL: %s", requestURL.String())
	httpRequest.Header.Set("Content-Type", "application/xml")

	httpResponse, err := util.SendRequest(httpRequest, tc.AasURL, tc.ServiceUsername, tc.ServicePassword, tc.TrustedCaCerts)
	if err != nil {
		return measurement, errors.Wrap(err, "client/trust_agent_client:GetMeasurementFromManifest() Error while getting response"+
			" from Host application measurement from TA API")
	}

	err = xml.Unmarshal(httpResponse, &measurement)
	if err != nil {
		return measurement, errors.Wrap(err, "client/trust_agent_client:GetMeasurementFromManifest() Error while unmarshalling"+
			" response from Host application measurement from TA API")
	}
	log.Info("clients/trust_agent_client:GetMeasurementFromManifest() Successfully received measurement for the " +
		"provided manifest")
	return measurement, nil
}

func (tc *taClient) GetBaseURL() *url.URL {
	return tc.BaseURL
}
