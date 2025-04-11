/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"net/http"

	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/auth"
	comctx "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/pkg/errors"

	"github.com/jinzhu/gorm"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

func PermissionsHandler(eh middleware.EndpointHandler, permissionNames []string) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:PermissionsHandler() Entering")
	defer defaultLog.Trace("router/handlers:PermissionsHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, writeErr := w.Write([]byte("Could not get user permissions from http context"))
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			if writeErr != nil {
				defaultLog.WithError(writeErr).Error("Failed to write response")
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

// Generic handler for writing response header and body for all handler functions
func ResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error), contentType string) middleware.EndpointHandler {
	defaultLog.Trace("router/handlers:ResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:ResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		if data != nil {
			_, err = w.Write([]byte(fmt.Sprintf("%v", data)))
			if err != nil {
				defaultLog.Errorf("router/handlers:ResponseHandler() Failed to write data")
			}
		}
		return nil
	}
}

func ErrorHandler(eh middleware.EndpointHandler) http.HandlerFunc {
	defaultLog.Trace("router/handlers:ErrorHandler() Entering")
	defer defaultLog.Trace("router/handlers:ErrorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
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
	case *commErr.BadRequestError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	}
	return err
}

type PrivilegeError struct {
	StatusCode int
	Message    string
}

func (e PrivilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type ResourceError struct {
	StatusCode int
	Message    string
}

func (e ResourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
