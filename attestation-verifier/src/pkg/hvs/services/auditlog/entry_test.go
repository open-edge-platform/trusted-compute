/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package auditlog

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func TestStructDiff(t *testing.T) {
	idNoChange, err := uuid.NewRandom()
	assert.NoError(t, err)
	hostId, err := uuid.NewRandom()
	assert.NoError(t, err)
	policyId, err := uuid.NewRandom()
	assert.NoError(t, err)
	aikId, err := uuid.NewRandom()
	assert.NoError(t, err)
	bkId, err := uuid.NewRandom()
	assert.NoError(t, err)
	rx := &models.HVSReport{
		ID:     idNoChange,
		HostID: hostId,
		TrustReport: hvs.TrustReport{
			PolicyName: policyId.String(),
			HostManifest: hvs.HostManifest{
				AIKCertificate:        aikId.String(),
				BindingKeyCertificate: bkId.String(),
			},
		},
	}
	hostId, err = uuid.NewRandom()
	assert.NoError(t, err)
	policyId, err = uuid.NewRandom()
	assert.NoError(t, err)
	aikId, err = uuid.NewRandom()
	assert.NoError(t, err)
	bkId, err = uuid.NewRandom()
	assert.NoError(t, err)
	ry := &models.HVSReport{
		ID:     idNoChange,
		HostID: hostId,
		TrustReport: hvs.TrustReport{
			PolicyName: policyId.String(),
			HostManifest: hvs.HostManifest{
				AIKCertificate:        aikId.String(),
				BindingKeyCertificate: bkId.String(),
			},
		},
	}
	newId, err := uuid.NewRandom()
	assert.NoError(t, err)
	aikId, err = uuid.NewRandom()
	assert.NoError(t, err)
	bkId, err = uuid.NewRandom()
	assert.NoError(t, err)
	hssx := &hvs.HostStatus{
		ID:     newId,
		HostID: idNoChange,
		HostManifest: hvs.HostManifest{
			AIKCertificate:        aikId.String(),
			BindingKeyCertificate: bkId.String(),
		},
		HostStatusInformation: hvs.HostStatusInformation{
			HostState: hvs.HostStateInvalid,
		},
	}
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	aikId, err = uuid.NewRandom()
	assert.NoError(t, err)
	bkId, err = uuid.NewRandom()
	assert.NoError(t, err)
	hssy := &hvs.HostStatus{
		ID:     newId,
		HostID: idNoChange,
		HostManifest: hvs.HostManifest{
			AIKCertificate:        aikId.String(),
			BindingKeyCertificate: bkId.String(),
		},
		HostStatusInformation: hvs.HostStatusInformation{
			HostState: hvs.HostStateInvalid,
		},
	}
	t.Log(report2Cols(rx, ry))
	t.Log(hostStatus2Cols(hssx, hssy))
}
