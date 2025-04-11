/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionController(t *testing.T) {
	router := mux.NewRouter()
	versionController := VersionController{}
	router.Handle("/version", versionController.GetVersion()).Methods(http.MethodGet)
	req, _ := http.NewRequest(http.MethodGet, "/version", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req)
	if !(w1.Code == http.StatusOK) {
		t.Error("version of cms and status ok should be returned")
	}
}
