/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wls"
	"github.com/pkg/errors"
	"io/ioutil"

	"github.com/google/uuid"
)

/**
 *
 * @author purvades
 */

// ImageFlavor is a flavor for an image with the encryption requirement information
// and key details of an encrypted image.
type ImageFlavor struct {
	Image wls.Image `json:"flavor"`
}

// GetImageFlavor is used to create a new image flavor with the specified label, encryption policy,
// key url, and digest of the encrypted image
func GetImageFlavor(label string, encryptionRequired bool, keyURL string, digest string) (*ImageFlavor, error) {
	log.Trace("flavor/image_flavor:GetImageFlavor() Entering")
	defer log.Trace("flavor/image_flavor:GetImageFlavor() Leaving")
	var encryption *wls.Encryption

	description := wls.Description{
		Label:      label,
		FlavorPart: "IMAGE",
	}

	meta := wls.Meta{
		Description: &description,
	}
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	meta.ID = newUuid

	if encryptionRequired {
		encryption = &wls.Encryption{
			KeyURL: keyURL,
			Digest: digest,
		}
	}

	imageflavor := wls.Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
	}

	flavor := ImageFlavor{
		Image: imageflavor,
	}
	return &flavor, nil
}

// GetContainerImageFlavor is used to create a new container image flavor with the specified label, encryption policy,
// Key url of the encrypted image also integrity policy and notary url for docker image signature verification
func GetContainerImageFlavor(label string, encryptionRequired bool, keyURL string, integrityEnforced bool, notaryURL string) (*ImageFlavor, error) {
	log.Trace("flavor/image_flavor:GetContainerImageFlavor() Entering")
	defer log.Trace("flavor/image_flavor:GetContainerImageFlavor() Leaving")
	var encryption *wls.Encryption
	var integrity *wls.Integrity

	if label == "" {
		return nil, errors.Errorf("label cannot be empty")
	}

	description := wls.Description{
		Label:      label,
		FlavorPart: "CONTAINER_IMAGE",
	}

	meta := wls.Meta{
		Description: &description,
	}
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	meta.ID = newUuid

	encryption = &wls.Encryption{
		KeyURL: keyURL,
	}

	integrity = &wls.Integrity{
		NotaryURL: notaryURL,
	}

	containerImageFlavor := wls.Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
		IntegrityEnforced:  integrityEnforced,
		Integrity:          integrity,
	}

	flavor := ImageFlavor{
		Image: containerImageFlavor,
	}
	return &flavor, nil
}

//GetSignedImageFlavor is used to sign image flavor
func GetSignedImageFlavor(flavorString string, rsaPrivateKeyLocation string) (string, error) {
	log.Trace("flavor/image_flavor:GetSignedImageFlavor() Entering")
	defer log.Trace("flavor/image_flavor:GetSignedImageFlavor() Leaving")
	var privateKey *rsa.PrivateKey
	var flavorInterface ImageFlavor
	if rsaPrivateKeyLocation == "" {
		log.Error("No RSA Key file path provided")
		return "", errors.New("No RSA Key file path provided")
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Error("No RSA private key found")
		return "", err
	}

	privPem, _ := pem.Decode(priv)
	parsedKey, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		log.Error("Cannot parse RSA private key from file")
		return "", err
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Error("Unable to parse RSA private key")
		return "", err
	}
	hashEntity := sha512.New384()
	hashEntity.Write([]byte(flavorString))

	digest := hashEntity.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, digest)
	signatureString := base64.StdEncoding.EncodeToString(signature)

	json.Unmarshal([]byte(flavorString), &flavorInterface)

	signedFlavor := &SignedImageFlavor{
		ImageFlavor: flavorInterface.Image,
		Signature:   signatureString,
	}

	signedFlavorJSON, err := json.Marshal(signedFlavor)
	if err != nil {
		return "", errors.New("Error while marshalling signed image flavor: " + err.Error())
	}

	return string(signedFlavorJSON), nil
}
