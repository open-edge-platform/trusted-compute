/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpm2utils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/types"
	"io"
	"math"

	"github.com/pkg/errors"
)

func isSupportedAsymAlgorithm(pubKey crypto.PublicKey) bool {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return true
	default:
		return false
	}
}

func isSupportedHashAlgorithm(hashAlg crypto.Hash) bool {
	switch hashAlg {
	case crypto.SHA256:
		return true
	default:
		return false
	}
}

/* MakeCredential function returns the Tpm2Credential which includes CredentialBlob, SecretBlob and Header
   Tpm2Credential.CredentialBlob and Tpm2Credential.SecretBlob will be among inputs to the TPM ActivateCredential
*/
func MakeCredential(ekPubKey crypto.PublicKey, symmetricAlgorithm string, symKeySizeInBits int, nameAlgorithm crypto.Hash, credential []byte, aikName []byte) (types.Tpm2Credential, error) {
	defaultLog.Trace("privacyca/tpm2utils/utils:MakeCredential() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:MakeCredential() Leaving")

	if credential == nil || len(credential) <= 0 {
		return types.Tpm2Credential{}, errors.New("privacyca/tpm2utils/utils:MakeCredential() credential is null or empty")
	}

	if aikName == nil || len(aikName) <= 0 {
		return types.Tpm2Credential{}, errors.New("privacyca/tpm2utils/utils:MakeCredential() aikName is null or empty")
	}

	if !isSupportedAsymAlgorithm(ekPubKey) {
		return types.Tpm2Credential{}, errors.New("privacyca/tpm2utils/utils:MakeCredential() Ek PubKey Algorithm is not (currently) supported")
	}

	if !isSupportedHashAlgorithm(nameAlgorithm) {
		return types.Tpm2Credential{}, errors.New("nameAlgorithm is not supported")
	}
	nameAlgDigestLength := nameAlgorithm.Size()
	if len(credential) > nameAlgDigestLength {
		return types.Tpm2Credential{}, errors.Errorf("privacyca/tpm2utils/utils:MakeCredential() Credential cannot be larger than %d bytes", nameAlgDigestLength)
	}
	var seed []byte
	encryptedSecretByteBuffer := new(bytes.Buffer)
	switch ekPubKey.(type) {
	case *rsa.PublicKey:
		{
			//Generate and encrypt the seed
			secretData, err := crypt.GetRandomBytes(32)
			if err != nil {
				return types.Tpm2Credential{}, errors.Wrap(err, "privacyca/tpm2utils/utils:MakeCredential() Unable to generate Random Bytes for Secret")
			}
			seed = secretData
			asymKey, err := crypt.GetRandomBytes(nameAlgDigestLength)
			if err != nil {
				return types.Tpm2Credential{}, errors.Wrap(err, "privacyca/tpm2utils/utils:MakeCredential() Unable to generate Random Bytes for entropy")
			}

			identityBuf := new(bytes.Buffer)
			err = binary.Write(identityBuf, binary.BigEndian, []byte(consts.IDENTITY))
			if err != nil {
				return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write identity")
			}
			err = binary.Write(identityBuf, binary.BigEndian, byte(0))
			if err != nil {
				return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write bytes")
			}

			switch nameAlgorithm {
			case crypto.SHA256:
				encryptedSecret, err := rsa.EncryptOAEP(sha256.New(), bytes.NewBuffer(asymKey), ekPubKey.(*rsa.PublicKey), secretData, identityBuf.Bytes())
				if err != nil {
					return types.Tpm2Credential{}, err
				}
				err = binary.Write(encryptedSecretByteBuffer, binary.BigEndian, uint16(len(encryptedSecret)))
				if err != nil {
					return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write secret size")
				}
				err = binary.Write(encryptedSecretByteBuffer, binary.BigEndian, encryptedSecret)
				if err != nil {
					return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write secret")
				}
				break
			default:
				return types.Tpm2Credential{}, errors.Errorf("privacyca/tpm2utils/utils:MakeCredential() Hashing Algorithm %s is not currently supported", crypt.GetHashingAlgorithmName(nameAlgorithm))
			}
		}
		break
	default:
		return types.Tpm2Credential{}, errors.New("privacyca/tpm2utils/utils:MakeCredential() Key Algorithm is not currently supported")
	}

	//Derive the symmetric key symKey using the seed
	symKey, err := KDFa(nameAlgorithm, seed, consts.STORAGE, aikName, nil, symKeySizeInBits)
	if err != nil {
		return types.Tpm2Credential{}, err
	}
	credentialBuf := new(bytes.Buffer)
	err = binary.Write(credentialBuf, binary.BigEndian, int16(len(credential)))
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write credential size")
	}
	err = binary.Write(credentialBuf, binary.BigEndian, credential)
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write credential")
	}
	credentialBytes := credentialBuf.Bytes()
	iv := make([]byte, aes.BlockSize)

	// Encrypt credential with Symmetric Algorithm using symKey
	encryptedCredential, err := EncryptSym(credentialBytes, symKey, iv, "CFB", symmetricAlgorithm)
	if err != nil {
		return types.Tpm2Credential{}, err
	}
	hmacKey, err := KDFa(nameAlgorithm, seed, consts.INTEGRITY, nil, nil, nameAlgDigestLength*8)
	if err != nil {
		return types.Tpm2Credential{}, err
	}

	if nameAlgorithm != crypto.SHA256 {
		return types.Tpm2Credential{}, errors.New("privacyca/tpm2utils/utils:MakeCredential() Unsupported algorithm for hmac")
	}

	//Calculate hmac sha256 digest of encryptedCredential and aikName
	mac := hmac.New(sha256.New, hmacKey)
	integrityBuf := new(bytes.Buffer)
	err = binary.Write(integrityBuf, binary.BigEndian, encryptedCredential)
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write credential")
	}
	err = binary.Write(integrityBuf, binary.BigEndian, aikName)
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write aik name")
	}
	_, err = mac.Write(integrityBuf.Bytes())
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrap(err, "privacyca/tpm2utils/utils:MakeCredential() Error while generating hmac hash")
	}
	integrity := mac.Sum(nil)

	credentialBlob := new(bytes.Buffer)
	err = binary.Write(credentialBlob, binary.BigEndian, int16(consts.SHORT_BYTES+len(integrity)+len(encryptedCredential)))
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write total length")
	}
	err = binary.Write(credentialBlob, binary.BigEndian, int16(len(integrity)))
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write integrity length")
	}
	err = binary.Write(credentialBlob, binary.BigEndian, integrity)
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write integrity")
	}
	err = binary.Write(credentialBlob, binary.BigEndian, encryptedCredential)
	if err != nil {
		return types.Tpm2Credential{}, errors.Wrapf(err, "privacyca/tpm2utils/utils:MakeCredential() Failed to write credential")
	}

	headerBlob := make([]byte, 8)
	binary.BigEndian.PutUint32(headerBlob, 0xBADCC0DE)
	binary.BigEndian.PutUint32(headerBlob, 1)

	tpm2Credential := types.Tpm2Credential{
		CredentialBlob: credentialBlob.Bytes(),
		HeaderBlob:     headerBlob,
		Secret:         encryptedSecretByteBuffer.Bytes(),
	}

	return tpm2Credential, nil
}

func KDFa(hashAlg crypto.Hash, key []byte, label string, contextU, contextV []byte, sizeInBits int) ([]byte, error) {
	defaultLog.Trace("privacyca/tpm2utils/utils:KDFa() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:KDFa() Leaving")

	if hashAlg != crypto.SHA256 {
		return nil, errors.Errorf("privacyca/tpm2utils/utils:KDFa() Algorithm: %s, is not a supported hashing algorithm", crypt.GetHashingAlgorithmName(hashAlg))
	}

	var labelBuf []byte
	if label != "" {
		labelBuf = []byte(label)
	}

	if ((sizeInBits + 7) / 8) > math.MaxInt16 {
		return nil, errors.New("privacyca/tpm2utils/utils:KDFa() sizeInBits is invalid ")
	}

	symBytesLen := (sizeInBits + 7) / 8
	hashLen := hashAlg.Size()
	counter := 0
	curPos := 0
	outBuf := make([]byte, symBytesLen)

	for symBytesLen > 0 {
		if symBytesLen < hashLen {
			hashLen = symBytesLen
		}
		counter = counter + 1
		mac := hmac.New(sha256.New, key)
		b := new(bytes.Buffer)
		err := binary.Write(b, binary.BigEndian, int32(counter))
		if err != nil {
			return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write couter")
		}

		err = binary.Write(b, binary.BigEndian, labelBuf)
		if err != nil {
			return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write label buffer")
		}

		err = binary.Write(b, binary.BigEndian, byte(0x00))
		if err != nil {
			return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write bytes")
		}

		if len(contextU) > 0 {
			err = binary.Write(b, binary.BigEndian, contextU)
			if err != nil {
				return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write contextU")
			}

		}
		if len(contextV) > 0 {
			err = binary.Write(b, binary.BigEndian, contextV)
			if err != nil {
				return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write contextV")
			}

		}
		err = binary.Write(b, binary.BigEndian, int32(sizeInBits))
		if err != nil {
			return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write bytes size")
		}

		_, err = mac.Write(b.Bytes())
		if err != nil {
			return nil, errors.Wrapf(err, "privacyca/tpm2utils/utils:KDFa() Failed to write bytes")
		}

		hmacHashValBytes := mac.Sum(nil)
		outBuf = hmacHashValBytes[curPos : curPos+hashLen]
		curPos += hashLen
		symBytesLen -= hashLen
	}

	// Now we handle the case where N bits is not a multpile of 8, such as 1001 bit key, which means we have 7 extra bits in our buffer
	if (sizeInBits % 8) != 0 {
		indexOutBuf := int16(outBuf[0])
		indexOutBuf = indexOutBuf & ((1 << uint16(sizeInBits%8)) - 1)
		outBuf[0] = byte(indexOutBuf)
	}

	return outBuf, nil
}

func EncryptSym(payload []byte, key []byte, iv []byte, encScheme string, algorithm string) ([]byte, error) {
	defaultLog.Trace("privacyca/tpm2utils/utils:EncryptSym() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:EncryptSym() Leaving")

	if len(payload) == 0 || len(key) == 0 || len(iv) == 0 {
		return nil, errors.New("privacyca/tpm2utils/utils:EncryptSym() Either key,payload or iv is empty")
	}
	if algorithm == "AES" {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errors.Wrap(err, "privacyca/tpm2utils/utils:EncryptSym() Error while getting aes cipher block")
		}
		switch encScheme {
		case "CBC":
			return encryptSymCBC(payload, block, iv), nil
		case "CFB":
			return encryptSymCFB(payload, block, iv), nil
		default:
			return nil, errors.New("privacyca/tpm2utils/utils:EncryptSym() Unsupported symmetric algorithm scheme")
		}
	} else {
		return nil, errors.New("Unsupported symmetric algorithm")
	}
}

func encryptSymCBC(payload []byte, block cipher.Block, iv []byte) []byte {
	defaultLog.Trace("privacyca/tpm2utils/utils:encryptSymCBC() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:encryptSymCBC() Leaving")
	mode := cipher.NewCBCEncrypter(block, iv)
	padding := block.BlockSize() - len(payload)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding := append(payload, padtext...)

	encryptedBytes := make([]byte, len(withPadding))
	mode.CryptBlocks(encryptedBytes, withPadding)

	return encryptedBytes
}

func encryptSymCFB(payload []byte, block cipher.Block, iv []byte) []byte {
	defaultLog.Trace("privacyca/tpm2utils/utils:encryptSymCFB() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:encryptSymCFB() Leaving")
	encryptedCredential := make([]byte, len(payload))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedCredential, payload)

	return encryptedCredential
}

func DecryptSym(payload []byte, key []byte, iv []byte, encScheme string, algorithm int) ([]byte, error) {
	defaultLog.Trace("privacyca/tpm2utils/utils:DecryptSym() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:DecryptSym() Leaving")

	if len(payload) == 0 || len(key) == 0 || len(iv) == 0 {
		return nil, errors.New("privacyca/tpm2utils/utils:DecryptSym() Either key, payload or iv is empty")
	}
	if algorithm == consts.TPM_ALG_AES {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errors.Wrap(err, "privacyca/tpm2utils/utils:DecryptSym() Error while getting aes cipher block")
		}
		switch encScheme {
		case "CBC":
			return decryptSymCBC(payload, block, iv), nil
		case "CBF":
			return decryptSymCBF(payload, block, iv), nil
		default:
			return nil, errors.New("privacyca/tpm2utils/utils:DecryptSym() Unsupported symmetric algorithm scheme")
		}
	} else {
		return nil, errors.New("privacyca/tpm2utils/utils:KDFa() Unsupported symmetric algorithm")
	}
}

func decryptSymCBC(payload []byte, block cipher.Block, iv []byte) []byte {
	defaultLog.Trace("privacyca/tpm2utils/utils:decryptSymCBC() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:decryptSymCBC() Leaving")
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedBytes := make([]byte, len(payload))
	mode.CryptBlocks(decryptedBytes, payload)

	length := len(decryptedBytes)
	unpadding := int(decryptedBytes[length-1])
	decryptedBytes = decryptedBytes[:(length - unpadding)]

	return decryptedBytes
}

func decryptSymCBF(payload []byte, block cipher.Block, iv []byte) []byte {
	defaultLog.Trace("privacyca/tpm2utils/utils:decryptSymCBF() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:decryptSymCBF() Leaving")
	mode := cipher.NewCFBDecrypter(block, iv)
	decryptedBytes := make([]byte, len(payload))
	mode.XORKeyStream(decryptedBytes, payload)

	return decryptedBytes
}

func Tpm2DecryptAsym(ciphertext []byte, key crypto.PrivateKey, encScheme int, label []byte) ([]byte, error) {
	defaultLog.Trace("privacyca/tpm2utils/utils:Tpm2DecryptAsym() Entering")
	defer defaultLog.Trace("privacyca/tpm2utils/utils:Tpm2DecryptAsym() Leaving")
	switch encScheme {
	case consts.TPM_ALG_ID_SHA256:
		var rng io.Reader
		decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rng, key.(*rsa.PrivateKey), ciphertext, label)
		if err != nil {
			return nil, errors.Wrap(err, "Error while decryption rsa")
		}
		return decryptedBytes, nil

	default:
		return rsa.DecryptPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), ciphertext)
	}
}
