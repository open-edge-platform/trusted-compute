/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/auth"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	comctx "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"net/http"
	"runtime/debug"
)

// Generic handler for writing response header and body for all handler functions
func ResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:ResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:ResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		w.WriteHeader(status)
		if data != nil {
			_, err = w.Write([]byte(fmt.Sprintf("%v", data)))
			if err != nil {
				defaultLog.WithError(err).Errorf("Error writing to response")
			}
		}
		return nil
	}
}

// JsonResponseHandler  is the same as http.JsonResponseHandler, but returns an error that can be handled by a generic
//// middleware handler
func JsonResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:JsonResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:JsonResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get("Accept") != constants.HTTPMediaTypeJson {
			return errorFormatter(&commErr.EndpointError{
				Message: "Invalid Accept type",
			}, http.StatusUnsupportedMediaType)
		}

		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		w.Header().Set("Content-Type", constants.HTTPMediaTypeJson)
		w.WriteHeader(status)
		if data != nil {
			// Send JSON response back to the client application
			err = json.NewEncoder(w).Encode(data)
			if err != nil {
				defaultLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
				secLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			}
		}
		return nil
	}
}

// XMLResponseHandler handler for writing response header and body for all handler functions that produces xml
func XMLResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:XMLResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:XMLResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get("Accept") != constants.HTTPMediaTypeXml {
			return errorFormatter(&commErr.EndpointError{
				Message: "Invalid Accept type",
			}, http.StatusUnsupportedMediaType)
		}
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		w.Header().Set("Content-Type", constants.HTTPMediaTypeXml)
		xmlResponseWriter(w, status, data)
		return nil
	}
}

func errorFormatter(err error, status int) error {
	defaultLog.Trace("router/handlers:errorFormatter() Entering")
	defer defaultLog.Trace("router/handlers:errorFormatter() Leaving")
	switch t := err.(type) {
	case *commErr.EndpointError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	case *commErr.ResourceError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	case *commErr.PrivilegeError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	}
	return err
}

func xmlResponseWriter(w http.ResponseWriter, status int, data interface{}) {
	defaultLog.Trace("router/handlers:xmlResponseWriter() Entering")
	defer defaultLog.Trace("router/handlers:xmlResponseWriter() Leaving")

	w.WriteHeader(status)
	if data != nil {
		// Send XML response back to the client application
		err := xml.NewEncoder(w).Encode(data)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			secLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
		}
	}
}

func PermissionsHandler(eh middleware.EndpointHandler, permissionNames []string) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:PermissionsHandler() Entering")
	defer defaultLog.Trace("router/handlers:PermissionsHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, writeErr := w.Write([]byte("Could not get user permissions from http context"))
			if writeErr != nil {
				defaultLog.WithError(writeErr).Errorf("Error writing to response")
			}
			secLog.Errorf("router/handlers:PermissionsHandler() %s Permission: %v | Context: %v", commLogMsg.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "router/handlers:PermissionsHandler() Could not get user permissions from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("router/handlers:PermissionsHandler() %s Insufficient privileges to access %s", commLogMsg.UnauthorizedAccess, r.RequestURI)
			return &commErr.PrivilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("router/handlers:PermissionsHandler() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

func ErrorHandler(eh middleware.EndpointHandler) http.HandlerFunc {
	defaultLog.Trace("router/handlers:ErrorHandler() Entering")
	defer defaultLog.Trace("router/handlers:ErrorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
				defaultLog.Error(string(debug.Stack()))
				http.Error(w, "Unknown Error", http.StatusInternalServerError)
			}
		}()
		if err := eh(w, r); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *commErr.HandledError:
				http.Error(w, t.Message, t.StatusCode)
			case *commErr.PrivilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}
