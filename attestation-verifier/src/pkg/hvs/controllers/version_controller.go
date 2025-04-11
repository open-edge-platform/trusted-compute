/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/version"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"net/http"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type VersionController struct {
}

func (controller VersionController) GetVersion(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/version:getVersion() Entering")
	defer defaultLog.Trace("controllers/version:getVersion() Leaving")

	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	return version.GetVersion(), http.StatusOK, nil
}
