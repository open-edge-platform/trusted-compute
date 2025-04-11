/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/version"
	"net/http"
)

type VersionController struct {
}

func (v VersionController) GetVersion() http.HandlerFunc {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")

	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("resource/version:getVersion() CMS version : %v", version.GetVersion())
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(version.GetVersion()))
		if err != nil {
			log.WithError(err).Error("Could not write version to response")
		}
	}
}
