/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package commands

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

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
	EVENT_LOG_DIGEST_SHA1     = "com.intel.mtwilson.core.common.model.MeasurementSha1"
	EVENT_LOG_DIGEST_SHA256   = "com.intel.mtwilson.core.common.model.MeasurementSha256"
	EVENT_NAME                = "OpenSource.EventName"
)

type pcrSelection struct {
	size        int
	hashAlg     uint16
	pcrSelected []byte
}

var PCR_NUMBER_PATTERN = regexp.MustCompile("[0-9]|[0-1][0-9]|2[0-3]")
var PCR_VALUE_PATTERN = regexp.MustCompile("[0-9a-fA-F]+")

func verifyQuoteAndGetPCRManifest(decodedEventLog string, verificationNonce []byte, tpmQuoteInBytes []byte,
	aikCertificate *x509.Certificate) (hvs.PcrManifest, error) {

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
	if !bytes.EqualFold(tpm2bData, verificationNonce) {
		// return types.PcrManifest{}, errors.New("internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest() Challenge " +
		// 	"and received nonce does not match")
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
	if pcrBankCount > MAX_PCR_BANKS {
		return hvs.PcrManifest{}, errors.New("internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest() AIK Quote " +
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
	index += 2
	tpm2bDigest := tpmQuoteInBytes[index : index+int(tpm2bDigestSize)]

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
	_ = binary.BigEndian.Uint16(tpmtSig[0:2])
	/* hashAlg used by the signature algorithm indicated above
	 * TPM_ALG_HASH
	 * for TPM_ALG_RSASSA, the default hash algorithm is TPM_ALG_SHA256 with value 0x000b
	 */
	pos += 2
	_ = binary.BigEndian.Uint16(tpmtSig[pos : pos+2])

	pos += 2
	tpmtSignatureSize := binary.BigEndian.Uint16(tpmtSig[pos : pos+2])

	pos += 2
	tpmtSignature := tpmtSig[pos : pos+tpmtSignatureSize]

	hash := sha256.New()
	hash.Write(quoteInfo)
	quoteDigest := hash.Sum(nil)
	err := rsa.VerifyPKCS1v15(aikCertificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, quoteDigest, tpmtSignature)
	if err != nil {
		// return types.PcrManifest{}, errors.Wrap(err, "util/aik_quote_verifier:verifyQuoteAndGetPCRManifest() "+
		// 	"Error verifying quote digest")
	}

	pos += tpmtSignatureSize
	pcrLen := uint16(len(tpmQuoteInBytes)) - (pos + tpmtSigIndex)
	if pcrLen <= 0 {
		return hvs.PcrManifest{}, errors.New("internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest() " +
			"AIK Quote verification failed, No PCR values included in quote")
	}
	pcrs := tpmtSig[pos : pos+pcrLen]
	pcrConcatLen := SHA256_SIZE * 24 * 3
	pcrPos := 0
	count := 0
	var pcrConcat []byte
	var pcrSize int
	var buffer bytes.Buffer

	for j := 0; j < int(pcrBankCount); j++ {
		hashAlg := pcrSelection[j].hashAlg
		if value, ok := hashAlgPcrSizeMap[int(hashAlg)]; ok {
			pcrSize = value
		} else {
			return hvs.PcrManifest{}, errors.New("internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest()" +
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
					buffer.WriteString(fmt.Sprintf("%2d ", pcr))
				} else if hashAlg == TPM_API_ALG_ID_SHA256 {
					buffer.WriteString(fmt.Sprintf("%2d_SHA256 ", pcr))
				}
				//Ignore the pcr banks other than SHA1 and SHA256
				if hashAlg == TPM_API_ALG_ID_SHA1 || hashAlg == TPM_API_ALG_ID_SHA256 {
					for i := 0; i < pcrSize; i++ {
						buffer.WriteString(fmt.Sprintf("%02x", pcrs[pcrPos+i]))
					}
				}
				buffer.WriteString("\n")
				count++
				pcrPos += pcrSize
			}
		}
	}
	hash = sha256.New()
	hash.Write(pcrConcat)
	quoteDigest = hash.Sum(nil)

	if !bytes.EqualFold(quoteDigest, tpm2bDigest) {
		return hvs.PcrManifest{}, errors.New("internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest() AIK Quote " +
			"verification failed, Digest of Concatenated PCR values does not match with PCR digest in the quote")
	}
	pcrManifest, err := createPCRManifest(strings.Split(buffer.String(), "\n"), decodedEventLog)
	if err != nil {
		return hvs.PcrManifest{}, errors.Wrap(err, "internal/aik_quote_verifier:verifyQuoteAndGetPCRManifest() Error "+
			"retrieving PCR manifest from quote")
	}
	return pcrManifest, nil
}

func createPCRManifest(pcrList []string, eventLog string) (hvs.PcrManifest, error) {

	var pcrManifest hvs.PcrManifest
	var err error
	pcrManifest.Sha256Pcrs = []hvs.HostManifestPcrs{}
	pcrManifest.Sha1Pcrs = []hvs.HostManifestPcrs{}

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
				shaAlgorithm, err := hvs.GetSHAAlgorithm(pcrBank)
				if err != nil {
					return pcrManifest, err
				}

				pcrIndex, err := hvs.GetPcrIndexFromString(pcrNumber)
				if err != nil {
					return pcrManifest, err
				}

				if strings.EqualFold(pcrBank, SHA256) {
					pcrManifest.Sha256Pcrs = append(pcrManifest.Sha256Pcrs, hvs.HostManifestPcrs{
						Index:   pcrIndex,
						Value:   pcrValue,
						PcrBank: shaAlgorithm,
					})
				} else if strings.EqualFold(pcrBank, SHA1) {
					pcrManifest.Sha1Pcrs = append(pcrManifest.Sha1Pcrs, hvs.HostManifestPcrs{
						Index:   pcrIndex,
						Value:   pcrValue,
						PcrBank: shaAlgorithm,
					})
				}
			} else {
			}
		}
	}
	pcrManifest.PcrEventLogMap, err = getPcrEventLog(eventLog)
	if err != nil {
		return pcrManifest, errors.Wrap(err, "internal/aik_quote_verifier:createPCRManifest() Error getting PCR "+
			"event log")
	}
	return pcrManifest, nil
}

func getPcrEventLog(eventLog string) (hvs.PcrEventLogMap, error) {

	var pcrEventLogMap hvs.PcrEventLogMap
	var measureLogs []hvs.TpmEventLog
	err := json.Unmarshal([]byte(eventLog), &measureLogs)
	if err != nil {
		return hvs.PcrEventLogMap{}, errors.Wrap(err, "internal/aik_quote_verifier:getPcrEventLog() Error "+
			"unmarshalling measureLog")
	}
	for _, module := range measureLogs {
		addPcrEntry(module, &pcrEventLogMap)
	}
	return pcrEventLogMap, nil
}

func addPcrEntry(module hvs.TpmEventLog, eventLogMap *hvs.PcrEventLogMap) {

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
}
