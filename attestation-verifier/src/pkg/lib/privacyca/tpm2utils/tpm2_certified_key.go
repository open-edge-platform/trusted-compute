/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpm2utils

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
)

type Tpm2CertifiedKey struct {
	Magic           [4]byte
	Type            [2]byte
	Tpm2bName       Tpm2bName
	Tpm2bData       Tpm2bData
	TpmsClockInfo   TpmsClockInfo
	FirmwareVersion [8]byte
	TpmuAttest      TpmuAttest
}

type Tpm2bName struct {
	Size uint16
	Name []byte
}

type Tpm2bData struct {
	Size   uint16
	Buffer []byte
}

type TpmsClockInfo struct {
	Clock        [8]byte
	ResetCount   uint32
	RestartCount uint32
	Safe         byte
}

type TpmuAttest struct {
	/* This corresponds to the TPMS_CERTIFY_INFO struct  */
	Tpm2bName Tpm2bName
}

func (tpm2CertifiedKey *Tpm2CertifiedKey) PopulateTpmCertifyKey20(tpmCertifiedKey []byte) error {
	defaultLog.Trace("tpm2utils/tpm2_certified_key:PopulateTpmCertifyKey20() Entering")
	defer defaultLog.Trace("tpm2utils/tpm2_certified_key:PopulateTpmCertifyKey20() Leaving")

	buf := bytes.NewBuffer(tpmCertifiedKey)
	err := binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.Magic)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading magic")
	}
	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.Type)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading key type")
	}

	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.Tpm2bName.Size)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading key name size")
	}
	tpm2CertifiedKey.Tpm2bName.Name = buf.Next(int(tpm2CertifiedKey.Tpm2bName.Size))

	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.Tpm2bData.Size)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading external info size")
	}
	tpm2CertifiedKey.Tpm2bData.Buffer = buf.Next(int(tpm2CertifiedKey.Tpm2bData.Size))

	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.TpmsClockInfo.Clock)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading clock")
	}
	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.TpmsClockInfo.ResetCount)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading reset count")
	}
	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.TpmsClockInfo.RestartCount)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading restart count")
	}
	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.TpmsClockInfo.Safe)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading safe")
	}

	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.FirmwareVersion)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading firmware version")
	}

	err = binary.Read(buf, binary.BigEndian, &tpm2CertifiedKey.TpmuAttest.Tpm2bName.Size)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading attestation information size")
	}
	tpm2CertifiedKey.TpmuAttest.Tpm2bName.Name = buf.Next(int(tpm2CertifiedKey.TpmuAttest.Tpm2bName.Size))
	return nil
}

func (tpm2CertifiedKey *Tpm2CertifiedKey) GetTpmtHashAlgDigest() (int, []byte, error) {
	defaultLog.Trace("tpm2utils/tpm2_certified_key:GetTpmtHashAlgDigest() Entering")
	defer defaultLog.Trace("tpm2utils/tpm2_certified_key:GetTpmtHashAlgDigest() Leaving")

	buf := bytes.NewBuffer(tpm2CertifiedKey.TpmuAttest.Tpm2bName.Name)
	var hashAlg int16
	err := binary.Read(buf, binary.BigEndian, &hashAlg)
	if err != nil {
		return 0, nil, errors.Wrap(err, "tpm2utils/tpm2_certified_key:Error reading hash algorithm")
	}
	digest := buf.Next(int(tpm2CertifiedKey.TpmuAttest.Tpm2bName.Size) - 2)
	if digest == nil {
		return 0, nil, errors.Wrap(err, "tpm2utils/tpm2_certified_key:Digest bytes are empty")
	}
	return int(hashAlg), digest, nil
}
