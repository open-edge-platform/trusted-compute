/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type TpmEndorsementsClient interface {
	IsEkRegistered(hardwareUUID string) (bool, error)
	RegisterEk(tpmEndorsement *hvs.TpmEndorsement) error
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type tpmEndorsementsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *tpmEndorsementsClientImpl) IsEkRegistered(hardwareUUID string) (bool, error) {
	log.Trace("hvsclient/tpm_endorsement_client:IsEkRegistered() Entering")
	defer log.Trace("hvsclient/tpm_endorsement_client:IsEkRegistered() Leaving")

	url := fmt.Sprintf("%stpm-endorsements?hardwareUuidEqualTo=%s", client.cfg.BaseURL, hardwareUUID)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, errors.Wrap(err, "hvsclient/tpm_endorsement_client:IsEkRegistered() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return false, errors.Wrapf(err, "hvsclient/tpm_endorsement_client:IsEkRegistered() Error while sending request to %s ", url)
	}
	if response.StatusCode != http.StatusOK {
		return false, errors.Errorf("hvsclient/tpm_endorsement_client:IsEkRegistered() Request sent to %s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, errors.Wrap(err, "hvsclient/tpm_endorsement_client:IsEkRegistered() Error reading response")
	}

	var objmap map[string]interface{}
	if err := json.Unmarshal(data, &objmap); err != nil {
		return false, errors.Wrap(err, "hvsclient/tpm_endorsement_client:IsEkRegistered() Error while unmarshalling response body")
	}

	if objmap["tpm_endorsements"] != nil && len(objmap["tpm_endorsements"].([]interface{})) > 0 {
		// a endorsement was found with this hardware uuid
		return true, nil
	}

	return false, nil
}

func (client *tpmEndorsementsClientImpl) RegisterEk(tpmEndorsement *hvs.TpmEndorsement) error {
	log.Trace("hvsclient/tpm_endorsement_client:RegisterEk() Entering")
	defer log.Trace("hvsclient/tpm_endorsement_client:RegisterEk() Leaving")

	jsonData, err := json.Marshal(tpmEndorsement)
	if err != nil {
		return err
	}

	log.Tracef("hvsclient/tpm_endorsement_client:RegisterEk() Request body %s", string(jsonData))

	url := fmt.Sprintf("%stpm-endorsements", client.cfg.BaseURL)
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return errors.Wrap(err, "hvsclient/tpm_endorsement_client:RegisterEk() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return errors.Wrapf(err, "hvsclient/tpm_endorsement_client:RegisterEk() Error while sending request to %s ", url)
	}
	if response.StatusCode != http.StatusCreated {
		return errors.Errorf("hvsclient/tpm_endorsement_client:RegisterEk() Request sent to %s returned status %d", url, response.StatusCode)
	}

	return nil
}
