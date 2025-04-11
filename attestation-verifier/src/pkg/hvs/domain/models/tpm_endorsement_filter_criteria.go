/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import "github.com/google/uuid"

type TpmEndorsementFilterCriteria struct {
	Id                       uuid.UUID
	HardwareUuidEqualTo      uuid.UUID
	IssuerEqualTo            string
	IssuerContains           string
	RevokedEqualTo           bool
	CommentEqualTo           string
	CommentContains          string
	CertificateDigestEqualTo string
	Limit                    int
	AfterId                  int
}
