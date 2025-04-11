/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

func (handler *requestHandlerImpl) GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest,
	aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error) {

	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		return nil, err
	}

	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrapf(err, "common/quote:getTpmQuote() %s - Error creating tpm provider", message.AppRuntimeErr)
	}
	defer tpm.Close()

	if quoteRequest == nil {
		return nil, errors.New("common/quote:getTpmQuote() - TPM quote request cannot be nil")
	}
	return CreateTpmQuoteResponse(handler.cfg, tpm, quoteRequest, aikCertPath, measureLogFilePath, ramfsDir)
}

func CreateTpmQuoteResponse(cfg *config.TrustAgentConfiguration, tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest,
	aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error) {

	var err error

	log.Debugf("TpmQuoteRequest: %+v", tpmQuoteRequest)

	if len(tpmQuoteRequest.Nonce) == 0 {
		secLog.Errorf("common/quote:CreateTpmQuoteResponse() %s - The TpmQuoteRequest does not contain a nonce", message.InvalidInputProtocolViolation)
		return nil, errors.New("The TpmQuoteRequest does not contain a nonce")
	}

	// ISECL-12121: strip inactive PCR Banks from the request
	if len(tpmQuoteRequest.PcrBanks) == 0 {
		tpmQuoteRequest.PcrBanks = []string{string(constants.SHA384), string(constants.SHA256), string(constants.SHA1)}
	}

	for i, pcrBank := range tpmQuoteRequest.PcrBanks {
		isActive, err := tpm.IsPcrBankActive(pcrBank)
		if !isActive {
			log.WithError(err).Debugf("common/quote:CreateTpmQuoteResponse() %s PCR bank is inactive. Dropping from quote request",
				pcrBank)
			tpmQuoteRequest.PcrBanks = append(tpmQuoteRequest.PcrBanks[:i], tpmQuoteRequest.PcrBanks[i+1:]...)
		} else if err != nil {
			log.WithError(err).Warnf("common/quote:CreateTpmQuoteResponse() Error while determining PCR bank "+
				"%s state: %s", pcrBank, err.Error())
		}
	}

	tpmQuoteResponse, err := createTpmQuote(cfg.ImaMeasureEnabled, cfg.Tpm.TagSecretKey, tpm, tpmQuoteRequest, aikCertPath, measureLogFilePath, ramfsDir)
	if err != nil {
		return nil, errors.Wrapf(err, "common/quote:CreateTpmQuoteResponse() %s - Error while creating the tpm quote", message.AppRuntimeErr)
	}

	return tpmQuoteResponse, nil
}

// HVS generates a 20 byte random nonce that is sent in the tpmQuoteRequest.  However,
// HVS expects the response nonce (in the TpmQuoteResponse.Quote binary) to be hashed with the bytes
// of local ip address.  If this isn't performed, HVS will throw an error when the
// response is received.
//
// Also, HVS takes into account the asset tag in the nonce -- it takes the ip hashed nonce
// and 'extends' it with value of asset tag (i.e. when tags have been set on the trust agent).
func getNonce(tpmQuoteRequest *taModel.TpmQuoteRequest, assetTag string) ([]byte, error) {
	log.Trace("common/quote:getNonce() Entering")
	defer log.Trace("common/quote:getNonce() Leaving")

	log.Debugf("common/quote:getNonce() Received HVS nonce '%s', raw[%s]", base64.StdEncoding.EncodeToString(tpmQuoteRequest.Nonce), hex.EncodeToString(tpmQuoteRequest.Nonce))

	// similar to HVS' SHA1.digestOf(hvsNonce).extend(ipBytes)
	hash := sha256.New()
	_, err := hash.Write(tpmQuoteRequest.Nonce)
	if err != nil {
		return nil, err
	}
	taNonce := hash.Sum(nil)

	if assetTag != "" {

		tagBytes, err := base64.StdEncoding.DecodeString(assetTag)
		if err != nil {
			return nil, err
		}

		// similar to HVS' SHA1.digestOf(taNonce).extend(tagBytes)
		hash = sha256.New()
		_, err = hash.Write(taNonce)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(tagBytes)
		if err != nil {
			return nil, err
		}
		taNonce = hash.Sum(nil)

		log.Debugf("common/quote:getNonce() Used tag bytes '%s' to extend nonce to '%s', raw[%s]", hex.EncodeToString(tagBytes), base64.StdEncoding.EncodeToString(taNonce), hex.EncodeToString(taNonce))
	}

	return taNonce, nil
}

func readAikAsBase64(aikCertPath string) (string, error) {
	log.Trace("common/quote:readAikAsBase64() Entering")
	defer log.Trace("common/quote:readAikAsBase64() Leaving")

	if _, err := os.Stat(aikCertPath); os.IsNotExist(err) {
		return "", err
	}

	aikBytes, err := ioutil.ReadFile(aikCertPath)
	if err != nil {
		return "", errors.Wrapf(err, "common/quote:readAikAsBase64() Error reading file %s", aikCertPath)
	}

	return base64.StdEncoding.EncodeToString(aikBytes), nil
}

func readEventLog(measureLogFilePath string) (string, error) {
	log.Trace("common/quote:readEventLog() Entering")
	defer log.Trace("common/quote:readEventLog() Leaving")

	if _, err := os.Stat(measureLogFilePath); os.IsNotExist(err) {
		log.Debugf("esource/quote:readEventLog() Event log file '%s' was not present", measureLogFilePath)
		return "", nil // If the file does not exist, do not include in the quote
	}

	eventLogBytes, err := ioutil.ReadFile(measureLogFilePath)
	if err != nil {
		return "", errors.Wrapf(err, "common/quote:readEventLog() Error reading file: %s", measureLogFilePath)
	}

	// Make sure the bytes are valid json
	err = json.Unmarshal(eventLogBytes, new(interface{}))
	if err != nil {
		return "", errors.Wrap(err, "common/quote:readEventLog() Error while unmarshalling event log")
	}

	return string(eventLogBytes), nil
}

func getQuote(tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest, nonce []byte) (string, error) {

	log.Debugf("common/quote:getQuote() Providing tpm nonce value '%s', raw[%s]", base64.StdEncoding.EncodeToString(nonce), hex.EncodeToString(nonce))
	quoteBytes, err := tpm.GetTpmQuote(nonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(quoteBytes), nil
}

// create an array of "tcbMeasurments", each from the  xml escaped string
// of the files located in /opt/trustagent/var/ramfs
func getTcbMeasurements(ramfsDir string) ([]string, error) {
	log.Trace("common/quote:getTcbMeasurements() Entering")
	defer log.Trace("common/quote:getTcbMeasurements() Leaving")

	measurements := []string{}

	fileInfo, err := ioutil.ReadDir(ramfsDir)
	if err != nil {
		return nil, err
	}

	for _, file := range fileInfo {
		if filepath.Ext(file.Name()) == ".xml" {
			log.Debugf("common/quote:getTcbMeasurements() Including measurement file '%s/%s'", ramfsDir, file.Name())
			xml, err := ioutil.ReadFile(path.Join(ramfsDir, file.Name()))
			if err != nil {
				return nil, errors.Wrapf(err, "common/quote:getTcbMeasurements() Error reading manifest file %s", file.Name())
			}

			measurements = append(measurements, string(xml))
		}
	}

	return measurements, nil
}

func getAssetTags(tagSecretKey string, tpm tpmprovider.TpmProvider) (string, error) {
	log.Trace("common/quote:getAssetTags() Entering")
	defer log.Trace("common/quote:getAssetTags() Leaving")

	tagExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return "", errors.Wrap(err, "common/quote:getAssetTags() Error while checking existence of Nv Index")
	}

	if !tagExists {
		log.Warn("The asset tag nvram is not present")
		return "", nil
	}

	indexBytes, err := tpm.NvRead(tagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return "", errors.Wrap(err, "resource/quote:getAssetTags() Error while performing tpm nv read operation")
	}

	if indexBytes == nil {
		return "", errors.New("The tag data was nil")
	} else if len(indexBytes) != constants.TagIndexSize {
		return "", errors.Errorf("Invalid tag index length %d", len(indexBytes))
	}

	//
	// The v4.0 Trust-Agent allocates the tag index during 'tagent setup'.  At that
	// time, the index is filled with zeros.  If the all of the bytes are zero, then
	// a tag has not been deployed so return "" to indicate 'no tag present'.
	//
	allZeros := true
	for _, v := range indexBytes {
		if v != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(indexBytes), nil // this data will be evaluated in 'getNonce'
}

func createTpmQuote(isTAImaEnabled bool, tagSecretKey string, tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest,
	aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error) {
	log.Trace("common/quote:createTpmQuote() Entering")
	defer log.Trace("common/quote:createTpmQuote() Leaving")

	var err error

	tpmQuoteResponse := &taModel.TpmQuoteResponse{
		TimeStamp: time.Now().Unix(),
	}

	// getAssetTags must be called before getQuote so that the nonce is created correctly - see comments for getNonce()
	tpmQuoteResponse.AssetTag, err = getAssetTags(tagSecretKey, tpm)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving asset tags")
	}

	if tpmQuoteResponse.AssetTag != "" {
		tpmQuoteResponse.IsTagProvisioned = true
	}

	nonce, err := getNonce(tpmQuoteRequest, tpmQuoteResponse.AssetTag)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while generating nonce")
	}

	log.Debugf("NONCE: %+v", nonce)

	// get the quote from tpmprovider
	tpmQuoteResponse.Quote, err = getQuote(tpm, tpmQuoteRequest, nonce)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving tpm quote request")
	}

	// aik --> read from disk and convert to PEM string
	tpmQuoteResponse.Aik, err = readAikAsBase64(aikCertPath)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while reading Aik as Base64")
	}

	// eventlog: read /opt/trustagent/var/measure-log.json
	tpmQuoteResponse.EventLog, err = readEventLog(measureLogFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while reading event log")
	}

	switch {
	//check here both input request from hvs and ta has ima_enabled as true, then only proceed further
	case tpmQuoteRequest.ImaMeasureEnabled && isTAImaEnabled:
		// imaLog: read /sys/kernel/security/ima/ascii_runtime_measurements
		imaPath := &ImaPaths{
			ProcFilePath:  constants.ProcFilePath,
			AsciiFilePath: constants.AsciiRuntimeMeasurementFilePath,
		}

		imaInfo, err := imaPath.getImaMeasurements()
		if err != nil {
			return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while reading ima log")
		}
		tpmQuoteResponse.ImaLogs = imaInfo.ImaLog
	case isTAImaEnabled == false:
		log.Warnf("common/quote:createTpmQuote() IMA is not enabled in TrustAgent")
	case tpmQuoteRequest.ImaMeasureEnabled == false:
		log.Warnf("common/quote:createTpmQuote() IMA is not enabled in Tpm-Quote Request Body")
	default:
		log.Warnf("common/quote:createTpmQuote() IMA is not enabled in TrustAgent and Tpm-Quote Request Body")
	}

	tpmQuoteResponse.TcbMeasurements.TcbMeasurements, err = getTcbMeasurements(ramfsDir)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving TCB measurements")
	}

	// selected pcr banks (just return what was requested similar to java implementation)
	tpmQuoteResponse.SelectedPcrBanks.SelectedPcrBanks = tpmQuoteRequest.PcrBanks

	tpmQuoteResponse.ErrorCode = 0 // Question: does HVS handle specific error codes or is just a pass through?
	tpmQuoteResponse.ErrorMessage = "OK"
	return tpmQuoteResponse, nil
}
