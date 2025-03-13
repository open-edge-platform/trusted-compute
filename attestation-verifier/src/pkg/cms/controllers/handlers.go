/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/pkg/errors"
	"fmt"
	"net/http"

	clog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"gorm.io/gorm"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Trace("resource/resource:ServeHTTP() Entering")
	defer log.Trace("resource/resource:ServeHTTP() Leaving")

	if err := ehf(w, r); err != nil {
		log.WithError(err).Error("HTTP Error")
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle record not found error...
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		switch t := err.(type) {
		case *resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")

	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")

	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
