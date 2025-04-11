/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"regexp"
	"strconv"
	"strings"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

const (
	SHA1_SIZE                 = 20
	SHA256_SIZE               = 32
	SHA384_SIZE               = 48
	SHA512_SIZE               = 64
	TPM_API_ALG_ID_SHA1       = 0x04
	TPM_API_ALG_ID_SHA256     = 0x0B
	TPM_API_ALG_ID_SHA384     = 0x0C
	TPM_API_ALG_ID_SHA512     = 0x0D
	TPM_API_ALG_ID_SM3_SHA256 = 0x12
	MAX_PCR_BANKS             = 5
	PCR_NUMBER_UNTAINT        = "[^0-9]"
	PCR_VALUE_UNTAINT         = "[^0-9a-fA-F]"
	SHA1                      = "SHA1"
	SHA256                    = "SHA256"
	SHA384                    = "SHA384"
	EVENT_LOG_DIGEST_SHA1     = "com.intel.mtwilson.core.common.model.MeasurementSha1"
	EVENT_LOG_DIGEST_SHA256   = "com.intel.mtwilson.core.common.model.MeasurementSha256"
	EVENT_LOG_DIGEST_SHA384   = "com.intel.mtwilson.core.common.model.MeasurementSha384"
	EVENT_NAME                = "OpenSource.EventName"
)

var PCR_NUMBER_PATTERN = regexp.MustCompile("[0-9]|[0-1][0-9]|2[0-3]")
var PCR_VALUE_PATTERN = regexp.MustCompile("[0-9a-fA-F]+")

type pcrSelection struct {
	size        int
	hashAlg     uint16
	pcrSelected []byte
}

func GetPCRManifest(decodedEventLog string, buffer bytes.Buffer) (hvs.PcrManifest, error) {
	log.Trace("util/aik_quote_verifier:GetPCRManifest() Entering")
	defer log.Trace("util/aik_quote_verifier:GetPCRManifest() Leaving")

	pcrManifest, err := createPCRManifest(strings.Split(buffer.String(), "\n"), decodedEventLog)
	if err != nil {
		return hvs.PcrManifest{}, errors.Wrap(err, "util/aik_quote_verifier:GetPCRManifest() Error "+
			"retrieving PCR manifest from quote")
	}
	log.Info("util/aik_quote_verifier:GetPCRManifest() Successfully created PCR manifest")
	return pcrManifest, nil
}

func VerifyQuoteAndGetPCRDetails(verificationNonce []byte, tpmQuoteInBytes []byte, aikCertificate *x509.Certificate) ([]byte, bytes.Buffer, error) {
	log.Trace("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() Entering")
	defer log.Trace("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() Leaving")

	hashAlgPcrSizeMap := make(map[int]int)
	hashAlgPcrSizeMap[TPM_API_ALG_ID_SHA1] = SHA1_SIZE
	hashAlgPcrSizeMap[TPM_API_ALG_ID_SHA256] = SHA256_SIZE
	hashAlgPcrSizeMap[TPM_API_ALG_ID_SHA384] = SHA384_SIZE
	hashAlgPcrSizeMap[TPM_API_ALG_ID_SHA512] = SHA512_SIZE
	hashAlgPcrSizeMap[TPM_API_ALG_ID_SM3_SHA256] = SHA256_SIZE

	//Get the length of quote
	index := 0
	quoteInfoLen := binary.BigEndian.Uint16(tpmQuoteInBytes[0:2])

	index += 2
	quoteInfo := tpmQuoteInBytes[index : index+int(quoteInfoLen)]

	index += 6
	tpm2bNameSize := binary.BigEndian.Uint16(tpmQuoteInBytes[index : index+2])

	index += 2 + int(tpm2bNameSize)
	tpm2bDataSize := binary.BigEndian.Uint16(tpmQuoteInBytes[index : index+2])

	index += 2
	tpm2bData := tpmQuoteInBytes[index : index+int(tpm2bDataSize)]
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() "+
		"Received nonce is : %s", base64.StdEncoding.EncodeToString(tpm2bData))
	if !bytes.EqualFold(tpm2bData, verificationNonce) {
		return nil, bytes.Buffer{}, errors.New("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() Challenge " +
			"and received nonce does not match")
	}

	index += int(tpm2bDataSize)
	/* Parse quote file
	 * The quote result is constructed as follows for now
	 *
	 * part1: pcr values (0-23), sha1 pcr bank. so the length is 20*24=480
	 * part2: the quoted information: TPM2B_ATTEST
	 * part3: the signature: TPMT_SIGNATURE
	 */
	index += 17 // skip over the TPMS_CLOCKINFO structure - Not interested
	index += 8  // skip over the firmware info - Not interested

	pcrBankCount := binary.BigEndian.Uint32(tpmQuoteInBytes[index : index+4])
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() PCR bank count is : %v", pcrBankCount)
	if pcrBankCount > MAX_PCR_BANKS {
		return nil, bytes.Buffer{}, errors.New("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() AIK Quote " +
			"verification failed, Number of PCR selection array in " + "the quote is greater than 5. PCRBankCount " +
			": " + fmt.Sprint(pcrBankCount))
	}

	index += 4
	pcrSelection := make([]pcrSelection, pcrBankCount)
	for i := 0; i < int(pcrBankCount); i++ {
		pcrSelection[i].hashAlg = binary.BigEndian.Uint16(tpmQuoteInBytes[index : index+2])
		index += 2
		pcrSelection[i].size = int(tpmQuoteInBytes[index])
		index += 1
		pcrSelection[i].pcrSelected = tpmQuoteInBytes[index : index+pcrSelection[i].size]
		index += pcrSelection[i].size
	}

	tpm2bDigestSize := binary.BigEndian.Uint16(tpmQuoteInBytes[index : index+2])
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() tpm2bDigestSize is : %v", tpm2bDigestSize)
	index += 2
	tpm2bDigest := tpmQuoteInBytes[index : index+int(tpm2bDigestSize)]
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails()  PCR manifest digest: %v", tpm2bDigest)

	/* PART 2: TPMT_SIGNATURE
	Skip the first 2 bytes having the quote info size and remaining bytes, which includes signer info, nonce, pcr selection
	and extra data. So jump to TPMT_SIGNATURE
	*/

	tpmtSigIndex := 2 + quoteInfoLen
	tpmtSig := tpmQuoteInBytes[tpmtSigIndex:]
	var pos uint16 = 0
	/* sigAlg -indicates the signature algorithm TPMI_SIG_ALG_SCHEME
	 * for now, it is TPM_ALG_RSASSA with value 0x0014
	 */
	tpmtSignatureAlg := binary.BigEndian.Uint16(tpmtSig[0:2])
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() TPM signature Algorithm: %v", tpmtSignatureAlg)
	/* hashAlg used by the signature algorithm indicated above
	 * TPM_ALG_HASH
	 * for TPM_ALG_RSASSA, the default hash algorithm is TPM_ALG_SHA256 with value 0x000b
	 */
	pos += 2
	tpmtSignatureHashAlg := binary.BigEndian.Uint16(tpmtSig[pos : pos+2])
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() TPM signature Hash Algorithm: %v", tpmtSignatureHashAlg)

	pos += 2
	tpmtSignatureSize := binary.BigEndian.Uint16(tpmtSig[pos : pos+2])

	pos += 2
	tpmtSignature := tpmtSig[pos : pos+tpmtSignatureSize]
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() TPMT signature : %v", tpmtSignature)

	hash := sha256.New()
	_, err := hash.Write(quoteInfo)
	if err != nil {
		return nil, bytes.Buffer{}, errors.Wrap(err, "Error writing quote information")
	}
	pcrsDigest := hash.Sum(nil)
	secLog.Debugf("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() Quote signature : %v", pcrsDigest)
	err = rsa.VerifyPKCS1v15(aikCertificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, pcrsDigest, tpmtSignature)
	if err != nil {
		return nil, bytes.Buffer{}, errors.Wrap(err, "util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() "+
			"Error verifying pcrs digest")
	}

	pos += tpmtSignatureSize
	pcrLen := uint16(len(tpmQuoteInBytes)) - (pos + tpmtSigIndex)
	if pcrLen <= 0 {
		return nil, bytes.Buffer{}, errors.New("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() " +
			"AIK Quote verification failed, No PCR values included in quote")
	}
	pcrs := tpmtSig[pos : pos+pcrLen]
	pcrConcatLen := SHA256_SIZE * 24 * 3
	pcrPos := 0
	count := 0
	var pcrConcat []byte
	var pcrSize int
	var pcrBuffer bytes.Buffer

	for j := 0; j < int(pcrBankCount); j++ {
		hashAlg := pcrSelection[j].hashAlg
		if value, ok := hashAlgPcrSizeMap[int(hashAlg)]; ok {
			pcrSize = value
		} else {
			secLog.Error("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() "+
				"AIK Quote verification failed, Unsupported PCR banks, hash algorithm id : ", hashAlg)
			return nil, bytes.Buffer{}, errors.New("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails()" +
				"AIK Quote verification failed, Unsupported PCR banks, hash algorithm id : %s" + strconv.Itoa(int(hashAlg)))
		}
		/* For each pcr bank iterate through each pcr selection array.
		Here pcrSelection.pcrSelected byte array contains 3 elements, where each bit of this element corresponds to pcr entry.
		8 bits pcrSelection.pcrSelected value corresponds to 8 PCR entries.
		*/
		for pcr := 0; pcr < 8*pcrSelection[j].size; pcr++ {
			pcrSelected := pcrSelection[j].pcrSelected
			selected := pcrSelected[pcr/8] & (1 << (uint16(pcr) % 8))
			if selected > 0 {
				if (pcrPos + pcrSize) < pcrConcatLen {
					pcrConcat = append(pcrConcat, pcrs[pcrPos:pcrPos+pcrSize]...)
				}
				if hashAlg == TPM_API_ALG_ID_SHA1 {
					pcrBuffer.WriteString(fmt.Sprintf("%2d ", pcr))
				} else if hashAlg == TPM_API_ALG_ID_SHA256 {
					pcrBuffer.WriteString(fmt.Sprintf("%2d_SHA256 ", pcr))
				} else if hashAlg == TPM_API_ALG_ID_SHA384 {
					pcrBuffer.WriteString(fmt.Sprintf("%2d_SHA384 ", pcr))
				}
				//Ignore the pcr banks other than SHA1 SHA256 and SHA384
				if hashAlg == TPM_API_ALG_ID_SHA1 || hashAlg == TPM_API_ALG_ID_SHA256 || hashAlg == TPM_API_ALG_ID_SHA384 {
					for i := 0; i < pcrSize; i++ {
						pcrBuffer.WriteString(fmt.Sprintf("%02x", pcrs[pcrPos+i]))
					}
				}
				pcrBuffer.WriteString("\n")
				count++
				pcrPos += pcrSize
			}
		}
	}
	hash = sha256.New()
	_, err = hash.Write(pcrConcat)
	if err != nil {
		return nil, bytes.Buffer{}, errors.Wrap(err, "Error writing pcr hash")
	}
	pcrsDigest = hash.Sum(nil)

	if !bytes.EqualFold(pcrsDigest, tpm2bDigest) {
		log.Error("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() AIK Quote verification failed, Digest " +
			"of Concatenated PCR values does not match with PCR digest in the quote")
		return nil, bytes.Buffer{}, errors.New("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails() AIK Quote " +
			"verification failed, Digest of Concatenated PCR values does not match with PCR digest in the quote")
	}
	log.Info("util/aik_quote_verifier:VerifyQuoteAndGetPCRDetails()  Successfully verified AIK Quote")
	return pcrsDigest, pcrBuffer, nil
}

func GetVerificationNonce(nonce []byte, quoteResponse taModel.TpmQuoteResponse) (string, error) {
	log.Trace("util/aik_quote_verifier:GetVerificationNonce() Entering")
	defer log.Trace("util/aik_quote_verifier:GetVerificationNonce() Leaving")
	hash := sha256.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return "", err
	}
	taNonce := hash.Sum(nil)

	if quoteResponse.IsTagProvisioned {
		if quoteResponse.AssetTag == "" {
			return "", errors.New("util/aik_quote_verifier:GetVerificationNonce() The quote is " +
				"'tag provisioned', but the tag was not provided")
		}
		tagBytes, err := base64.StdEncoding.DecodeString(quoteResponse.AssetTag)
		if err != nil {
			return "", err
		}

		hash = sha256.New()
		_, err = hash.Write(taNonce)
		if err != nil {
			return "", err
		}
		_, err = hash.Write(tagBytes)
		if err != nil {
			return "", err
		}
		taNonce = hash.Sum(nil)
	}
	log.Debug("util/aik_quote_verifier:GetVerificationNonce() Verification Nonce generated")
	return base64.StdEncoding.EncodeToString(taNonce), nil
}

func createPCRManifest(pcrList []string, eventLog string) (hvs.PcrManifest, error) {

	log.Trace("util/aik_quote_verifier:createPCRManifest() Entering")
	defer log.Trace("util/aik_quote_verifier:createPCRManifest() Leaving")
	var pcrManifest hvs.PcrManifest
	var err error
	pcrManifest.Sha256Pcrs = []hvs.HostManifestPcrs{}
	pcrManifest.Sha1Pcrs = []hvs.HostManifestPcrs{}
	pcrManifest.Sha384Pcrs = []hvs.HostManifestPcrs{}

	for _, pcrString := range pcrList {
		parts := strings.Split(strings.TrimSpace(pcrString), " ")
		if len(parts) == 2 {
			/* parts[0] contains pcr index and the bank algorithm
			 * in case of SHA1, the bank algorithm is not attached. so the format is just the pcr number same as before
			 * in case of SHA256 or other algorithms, the format is "pcrNumber_SHA256"
			 */
			pcrIndexParts := strings.Split(strings.TrimSpace(parts[0]), "_")
			pcrNumber := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(pcrIndexParts[0]),
				PCR_NUMBER_UNTAINT, ""), "\n", "")
			var pcrBank string
			if len(pcrIndexParts) == 2 {
				pcrBank = strings.TrimSpace(pcrIndexParts[1])
			} else {
				pcrBank = SHA1
			}
			pcrValue := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(parts[1]), PCR_VALUE_UNTAINT, ""),
				"\n", "")

			if PCR_NUMBER_PATTERN.MatchString(pcrNumber) && PCR_VALUE_PATTERN.MatchString(pcrValue) {
				secLog.Debugf("Result PCR %s : %s", pcrNumber, pcrValue)
				shaAlgorithm, err := hvs.GetSHAAlgorithm(pcrBank)
				if err != nil {
					return pcrManifest, err
				}

				pcrIndex, err := hvs.GetPcrIndexFromString(pcrNumber)
				if err != nil {
					return pcrManifest, err
				}

				if strings.EqualFold(pcrBank, "SHA256") {
					pcrManifest.Sha256Pcrs = append(pcrManifest.Sha256Pcrs, hvs.HostManifestPcrs{
						Index:   pcrIndex,
						Value:   pcrValue,
						PcrBank: shaAlgorithm,
					})
				} else if strings.EqualFold(pcrBank, "SHA1") {
					pcrManifest.Sha1Pcrs = append(pcrManifest.Sha1Pcrs, hvs.HostManifestPcrs{
						Index:   pcrIndex,
						Value:   pcrValue,
						PcrBank: shaAlgorithm,
					})
				} else if strings.EqualFold(pcrBank, "SHA384") {
					pcrManifest.Sha384Pcrs = append(pcrManifest.Sha384Pcrs, hvs.HostManifestPcrs{
						Index:   pcrIndex,
						Value:   pcrValue,
						PcrBank: shaAlgorithm,
					})
				}
			} else {
				log.Warn("util/aik_quote_verifier:createPCRManifest() Result PCR invalid")
			}
		}
	}
	pcrManifest.PcrEventLogMap, err = getPcrEventLog(eventLog)
	if err != nil {
		log.Errorf("util/aik_quote_verifier:createPCRManifest() Error getting PCR event log : %s", err.Error())
		return pcrManifest, errors.Wrap(err, "util/aik_quote_verifier:createPCRManifest() Error getting PCR "+
			"event log")
	}
	return pcrManifest, nil
}

func getPcrEventLog(eventLog string) (hvs.PcrEventLogMap, error) {

	log.Trace("util/aik_quote_verifier:getPcrEventLog() Entering")
	defer log.Trace("util/aik_quote_verifier:getPcrEventLog() Leaving")

	var pcrEventLogMap hvs.PcrEventLogMap
	var measureLogs []hvs.TpmEventLog

	if eventLog == "" {
		return pcrEventLogMap, nil
	}

	err := json.Unmarshal([]byte(eventLog), &measureLogs)
	if err != nil {
		return hvs.PcrEventLogMap{}, errors.Wrap(err, "util/aik_quote_verifier:getPcrEventLog() Error unmarshalling measureLog")
	}

	for _, measureLog := range measureLogs {
		addPcrEntry(measureLog, &pcrEventLogMap)
	}
	return pcrEventLogMap, nil
}

func addPcrEntry(module hvs.TpmEventLog, eventLogMap *hvs.PcrEventLogMap) {

	log.Trace("util/aik_quote_verifier:addPcrEntry() Entering")
	defer log.Trace("util/aik_quote_verifier:addPcrEntry() Leaving")
	pcrFound := false
	index := 0
	switch module.Pcr.Bank {
	case SHA1:
		for _, entry := range eventLogMap.Sha1EventLogs {
			if entry.Pcr.Index == module.Pcr.Index {
				pcrFound = true
				break
			}
			index++
		}

		if !pcrFound {
			eventLogMap.Sha1EventLogs = append(eventLogMap.Sha1EventLogs, hvs.TpmEventLog{Pcr: hvs.Pcr{Index: module.Pcr.Index, Bank: SHA1}, TpmEvent: module.TpmEvent})
		} else {
			for _, events := range module.TpmEvent {
				eventLog := hvs.EventLog{Measurement: events.Measurement,
					Tags: events.Tags, TypeID: events.TypeID, TypeName: events.TypeName}

				eventLogMap.Sha1EventLogs[index].TpmEvent = append(eventLogMap.Sha1EventLogs[index].TpmEvent, eventLog)
			}
		}

	case SHA256:
		for _, entry := range eventLogMap.Sha256EventLogs {
			if entry.Pcr.Index == module.Pcr.Index {
				pcrFound = true
				break
			}
			index++
		}

		if !pcrFound {
			eventLogMap.Sha256EventLogs = append(eventLogMap.Sha256EventLogs, hvs.TpmEventLog{Pcr: hvs.Pcr{Index: module.Pcr.Index, Bank: SHA256}, TpmEvent: module.TpmEvent})
		} else {
			for _, events := range module.TpmEvent {
				eventLog := hvs.EventLog{Measurement: events.Measurement,
					Tags: events.Tags, TypeID: events.TypeID, TypeName: events.TypeName}
				eventLogMap.Sha256EventLogs[index].TpmEvent = append(eventLogMap.Sha256EventLogs[index].TpmEvent, eventLog)
			}
		}

	case SHA384:
		for _, entry := range eventLogMap.Sha384EventLogs {
			if entry.Pcr.Index == module.Pcr.Index {
				pcrFound = true
				break
			}
			index++
		}

		if !pcrFound {
			eventLogMap.Sha384EventLogs = append(eventLogMap.Sha384EventLogs, hvs.TpmEventLog{Pcr: hvs.Pcr{Index: module.Pcr.Index, Bank: SHA384}, TpmEvent: module.TpmEvent})
		} else {
			for _, events := range module.TpmEvent {
				eventLog := hvs.EventLog{Measurement: events.Measurement,
					Tags: events.Tags, TypeID: events.TypeID, TypeName: events.TypeName}
				eventLogMap.Sha384EventLogs[index].TpmEvent = append(eventLogMap.Sha384EventLogs[index].TpmEvent, eventLog)
			}
		}

	}
	log.Debugf("util/aik_quote_verifier:addPcrEntry() Successfully added PCR log entries")
}

func GenerateNonce(nonceSize int) (string, error) {
	log.Trace("util/aik_quote_verifier:GenerateNonce() Entering")
	defer log.Trace("util/aik_quote_verifier:GenerateNonce() Leaving")

	randomBytes := make([]byte, nonceSize)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(randomBytes), err
}
