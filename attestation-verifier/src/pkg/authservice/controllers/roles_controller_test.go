/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	comm "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres/mock"
	aasRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RolesController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var rolesController controllers.RolesController
	// mock database
	mockDatabase := &mock.MockDatabase{
		MockUserStore:       getMockUserStore(),
		MockRoleStore:       getMockRoleStore(),
		MockPermissionStore: getPermissionStore(),
	}
	comm.InitDefender(5, 5, 15)

	BeforeEach(func() {
		router = mux.NewRouter()
		rolesController = controllers.RolesController{
			Database: mockDatabase,
		}
	})

	Describe("RolesController", func() {

		// Validate CreateRole
		Context("Validate CreateRole", func() {
			// Invalid request with empty request body
			It("Should return StatusBadRequest - Empty request body provided", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/roles", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request body.
			It("Should return StatusBadRequest - Invalid request body", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)

				testRole := `{
					"service: "KBS",
					"name": "KBS_TEST",
					"context": "CN=KBS TEST Certificate;certType=TLS",
					"permissions": [
						"test:permission",
					]
				}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with no permissions info.
			It("Should return StatusUnauthorized - No permission added in request", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
							"service": "KBS",
							"name": "KBS_TEST",
							"context": "CN=KBS TEST Certificate;certType=TLS",
							"permissions": [
								"test:permission"
							]
						}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// To validate with invalid permissions info.
			It("Should return StatusUnauthorized - Invalid permission added in request", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "KBS_TEST",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{"test:test"},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// To validate with invalid RoleName to ValidateRoleString.
			It("Should return StatusBadRequest - Invalid RoleName given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid ServiceName
			It("Should return StatusBadRequest - Invalid ServiceName provided", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3",
								"name": "KBS_TEST",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid Context.
			It("Should return StatusBadRequest - Invalid Context provided", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "KBS_TEST",
								"context": "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxs",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid Permission
			It("Should return StatusBadRequest - Invalid permission given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "KBS_TEST",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxs"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate CreateRole with invalid permission.
			// This is simulated to get InternalServerError during permission creation.
			It("Should return StatusInternalServerError - Invalid permission provided", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
									"service": "KBS",
									"name": "KBS_TEST2",
									"context": "CN=KBS TEST Certificate;certType=TLS",
									"permissions": [
										"rule:InvalidRule"
									]
								}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// To validate with invalid role creation
			// This test is to simulate InternalServerError in RoleStore().Create()
			It("Should return StatusInternalServerError - Invalid role provided", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "AAS",
								"name": "invalid_role",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// To validate with invalid role creation
			It("Should return StatusForbidden - Invalid role creation with context", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "invalid_role",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
					Context: "Test_context",
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusForbidden))
			})
			// Valid request
			It("Should Create Role - Valid request", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)

				testRole := `{
					"service": "KBS",
					"name": "KBS_TEST",
					"context": "CN=KBS TEST Certificate;certType=TLS",
					"permissions": [
						"test:permission"
					]
				}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
			// To validate with the same Role
			It("Should return StatusBadRequest - Create exsisting role", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "KBS_TEST",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:permission"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Valid request with existing permission
			It("Should Create Role - Create with existing permission", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.CreateRole, "application/json"))).Methods(http.MethodPost)
				testRole := `{
								"service": "KBS",
								"name": "KBS_TEST1",
								"context": "CN=KBS TEST Certificate;certType=TLS",
								"permissions": [
									"test:testRule"
								]
							}`
				req, err := http.NewRequest(http.MethodPost, "/roles", strings.NewReader(testRole))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		// Validate GetRole
		Context("Validate GetRole", func() {
			// valid request
			It("Should return StatusOK - Valid request", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.GetRole, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// To validate with insufficient permission
			It("Should return StatusUnauthorized - Insufficient permission", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.GetRole, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// To validate StatusForbidden
			It("Should return StatusForbidden - Invalid context provided", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.GetRole, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleRetrieve},
					Context: "test_get_context",
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusForbidden))
			})
			// To validate with invalid UUID
			It("Should return StatusBadRequest - Invalid UUID provided", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.GetRole, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles/2b43be26-b0b8-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with unknown role
			It("Should return StatusNotFound - Unknown role requested", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.GetRole, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles/e690db01-35f8-449e-9815-c1ff596297a3", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		// Validate DeleteRole
		Context("Validate DeleteRole", func() {
			// valid request
			It("Should return StatusNoContent - Valid request should Delete Role", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/b860c076-0d96-45c2-bd3e-d63eb9f84e12", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
			// To validate with insufficent privilege
			It("Should return StatusUnauthorized - Insufficent privilege", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/b860c076-0d96-45c2-bd3e-d63eb9f84e12", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{"delete:permission"},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// To validate with invalid UUID
			It("Should return StatusBadRequest - Invalid UUID provided", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/6bbb7af8-b0bc-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with unknown role
			It("Should return StatusNotFound - Unknown role requested", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/0c523b56-2b0d-4ce3-a293-254bb9398c96", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
			// To validate with default role
			It("Should return StatusBadRequest - Shouldn't delete default role", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/c33deb88-e3f0-423a-a150-525991460c74", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate internal server error
			It("Should return StatusInternalServerError", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/8bd32e0a-da4f-4344-87d6-f68cee6999e8", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// To validate StatusForbidden
			It("Should return StatusForbidden - Invalid Context provided", func() {
				router.Handle("/roles/{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.DeleteRole, "application/json"))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/roles/8bd32e0a-da4f-4344-87d6-f68cee6999e8", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleDelete},
					Context: "test_delete_context",
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusForbidden))
			})
		})

		// Validate QueryRoles
		Context("Validate QueryRoles", func() {
			// valid request
			It("Should return StatusOK - Valid request shoudl return All Roles", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// To validate with insufficient privilege
			It("Should return StatusUnauthorized - Insufficient privilege", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// To validate with invalid query service
			It("Should return StatusBadRequest - Invalid query parameter(service) given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?service=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHI", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid query name
			It("Should return StatusBadRequest - Invalid query parameter(name) given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?name=mVYf0dddEtIDkPCi9FGI8erwmVYf0dddEtIDkPCi9FGI8erw", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid query context
			It("Should return StatusBadRequest - Invalid query parameter(context) given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?context=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxU", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with invalid query contextContains
			It("Should return StatusBadRequest - Invalid query parameter(contextContains) given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?contextContains=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxU", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate with query allContexts
			It("Should return StatusOK - Valid request with allContexts parameter, Should return All Roles", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?allContexts=true", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// To validate StatusInternalServerError
			It("Should return StatusInternalServerError - Invalid filter given", func() {
				router.Handle("/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.QueryRoles, "application/json"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/roles?name=invalid_filter", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.RoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		// Validate UpdateRole
		Context("Validate UpdateRole", func() {
			// Validate request is not implemented
			It("Should return StatusNotImplemented - Unsupported API", func() {
				router.Handle("/roles{id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(rolesController.UpdateRole, ""))).Methods(http.MethodPatch)
				req, err := http.NewRequest(http.MethodPatch, "/roles5c46d446-4107-46d5-afb6-d0f0ab04bc01", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotImplemented))
			})
		})
	})
})
