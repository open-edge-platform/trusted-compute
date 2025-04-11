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

var _ = Describe("UsersController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var userController controllers.UsersController
	// mock database
	mockDatabase := &mock.MockDatabase{
		MockUserStore:       getMockUserStore(),
		MockRoleStore:       getMockRoleStore(),
		MockPermissionStore: getPermissionStore(),
	}
	comm.InitDefender(5, 5, 15)

	BeforeEach(func() {
		router = mux.NewRouter()
		userController = controllers.UsersController{
			Database: mockDatabase,
		}
	})

	Describe("UsersController", func() {

		// Validate CreateUser
		Context("Validate CreateUser", func() {
			// Invalid request
			It("Should return StatusBadRequest - Empty request body provided", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/users", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Valid request
			It("Should return StatusCreated - Valid request should create user", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson := `{
						"username" : "testuser",
						"password" : "testpassword"
					}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
			// Invalid request body
			It("Should return StatusBadRequest - Invalid request body provieded", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson := `{
									"username : "testuser",
									"password" : "testpassword",
								}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request to validate username
			It("Should return StatusBadRequest - Invalid username given", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson := `{
									"username" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0",
									"password" : "testpassword"
								}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request to validate password
			It("Should return StatusBadRequest - Invalid password given", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson := `{
							"username" : "testusername",
							"password" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0"
						}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate existingUser
			It("Should return StatusBadRequest - Existing user details provided", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson := `{
							"username" : "existingUser",
							"password" : "testPassword"
						}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.CreateUser, "application/json"),
					[]string{constants.UserCreate}))).Methods(http.MethodPost)

				userJson1 := `{
								"username" : "internalUserError",
								"password" : "testPassword123"
							}`

				req, err := http.NewRequest(http.MethodPost, "/users", strings.NewReader(userJson1))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		// Validate GetUser
		Context("Validate GetUser", func() {
			// Invalid UUID request
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.GetUser, "application/json"),
					[]string{constants.UserRetrieve}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/4c5f37b2-b0df-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Valid request
			It("Should return StatusOK - Valid request should return user", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.GetUser, "application/json"),
					[]string{constants.UserRetrieve}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/1caea167-7430-4a65-89e7-425776bc2131", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Unknown user get request
			It("Should return StatusNotFound - Unknown user ID requested", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.GetUser, "application/json"),
					[]string{constants.UserRetrieve}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/4e6209c2-a581-47ba-bcd2-401c65d01f7c", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		// Validate UpdateUser
		Context("Validate UpdateUser", func() {
			// Invalid UUID request
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				req, err := http.NewRequest(http.MethodPatch, "/users/4c5f37b2-b0df-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with empty body content
			It("Should return StatusBadRequest - Empty body content", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Unknown user get request
			It("Should return StatusNotFound - Unknown user requested", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				req, err := http.NewRequest(http.MethodPatch, "/users/4e6209c2-a581-47ba-bcd2-401c65d01f7c", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
			// Valid request
			It("Should return StatusOK - Valid request should update user", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
						"username" : "test_user",
						"password" : "testAdminPassword"
					  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Invalid request with empty fields
			It("Should return StatusBadRequest - Empty fields provided in request body", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
						"username" : "",
						"password" : ""
					  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should return StatusBadRequest - Invalid username given", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
						"username" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg",
						"password" : "testpassword"
					  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid password
			It("Should StatusBadRequest - Invalid password given", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
						"username" : "test_user",
						"password" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg"
					  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request bad body content
			It("Should return StatusBadRequest - Invalid body content provided", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
									"username : "testusernam",
									"password" : "test",
								  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/1caea167-7430-4a65-89e7-425776bc2131", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request
			It("Should return StatusBadRequest - Invalid request, existing user given", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
									"username" : "test_user_exists",
									"password" : "testAdminPassword"
								  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/34a8e1bb-1d9d-44a7-958e-a15352e53103", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// To validate internal server error
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.UpdateUser, "application/json"),
					[]string{constants.UserStore}))).Methods(http.MethodPatch)

				userPatchJson := `{
									"username" : "internalUserError_update",
									"password" : "testAdminPassword"
								  }`
				req, err := http.NewRequest(http.MethodPatch, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9", strings.NewReader(userPatchJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserStore},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		// Validate DeleteUser
		Context("Validate DeleteUser", func() {
			// Invalid UUID request
			It("Should return StatusBadRequest - Invalid UUID provided", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.DeleteUser, "application/json"),
					[]string{constants.UserDelete}))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/4c5f37b2-b0df-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// valid request
			It("Should return StatusNoContent - Valid request should delete user", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.DeleteUser, "application/json"),
					[]string{constants.UserDelete}))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
			// Validate StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.DeleteUser, "application/json"),
					[]string{constants.UserDelete}))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// To validate Delete unknown user
			It("Should return StatusNotFound - Unknown user ID requested", func() {
				router.Handle("/users/{id}", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.DeleteUser, "application/json"),
					[]string{constants.UserDelete}))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/2a61d9eb-267c-4519-939a-a076c60eae46", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		// Validate QueryUsers
		Context("Validate QueryUsers", func() {
			// Valid request
			It("Should return StatusOK - Valid request should Retrieve all users", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.QueryUsers, "application/json"),
					[]string{constants.UserSearch}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Valid request
			It("Should return StatusOK - Valid request with query paramenter should retrieve user", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.QueryUsers, "application/json"),
					[]string{constants.UserSearch}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users?name=test_user", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Validate  StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.QueryUsers, "application/json"),
					[]string{constants.UserSearch}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users?name=internalUserError_update", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// Validate  Invalid name in query
			It("Should return StatusBadRequest - Invalid query parameter(name) value given", func() {
				router.Handle("/users", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(userController.QueryUsers, "application/json"),
					[]string{constants.UserSearch}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users?name=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// Validate AddUserRoles
		Context("Validate AddUserRoles", func() {
			// Invalid request
			It("Should return StatusBadRequest - Empty request body provided", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/users/9bff2e90-6ff6-46c3-868b-bafbc7de483d/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid UUID request
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/users/82426ade-b17a-11ec-b909-0242ac120002/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request body
			It("Should return StatusBadRequest - Invalid request body provided", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `    {
								"role_ids: ["41e56e88-4144-4506-91f7-8d0391e6f04b"],
							}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Unauthorized request
			It("Should return StatusUnauthorized - Insufficient permission", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `    {
					"role_ids": ["41e56e88-4144-4506-91f7-8d0391e6f04b"]
				}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Valid request
			It("Should return StatusCreated - Valid request, should Add role to user", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `    {
					"role_ids": ["41e56e88-4144-4506-91f7-8d0391e6f04b"]
				}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})

			// Invalid request with no rolesID
			It("Should return StatusBadRequest - Empty role_ids given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `    {
								"role_ids": []
							}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			// Invalid request with invalid roles UUID
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `{
								"role_ids": ["9b94b1ca-b186-11ec-b909-0242ac120002"]
							}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			// Invalid request with invalid rolesID
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `{
								"role_ids": ["565baa0b-910f-41b8-840d-9a2be15a7e38"]
							}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid legnth of rolesID
			It("Should return StatusBadRequest - Invalid length of rolesID", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `{
								"role_ids": ["de6e6ee5-0369-43f2-9e88-969214cdac1c"]
							}`

				req, err := http.NewRequest(http.MethodPost, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request failed to retrieve user
			It("Should return StatusBadRequest - Unknown user ID given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `{
							"role_ids": ["41e56e88-4144-4506-91f7-8d0391e6f04b"]
						}`

				req, err := http.NewRequest(http.MethodPost, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a0/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request failed to add role
			It("Should return StatusBadRequest - To validate roles ID with DB", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.AddUserRoles, "application/json"))).Methods(http.MethodPost)
				rolesJson := `{
							"role_ids": ["14babd0e-9980-4aa7-a248-3a35a92ff6d4"]
						}`

				req, err := http.NewRequest(http.MethodPost, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/roles", strings.NewReader(rolesJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// Validate QueryUserRoles
		Context("Validate QueryUserRoles", func() {
			// Valid request
			It("Should return StatusOK - Valid request, should return roles", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Unauthorized request
			It("Should return StatusUnauthorized - Insufficient permission", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid UUID request
			It("Should return StatusBadRequest - Invalid UUID given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/5fc78b64-b18f-11ec-b909-0242ac120002/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with query name
			It("Should return StatusBadRequest - Invalid query parameter(name) value given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles?name=mVYf0dEtkasdasdkdIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUH", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with query service
			It("Should return StatusBadRequest - Invalid query parameter(service) value given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles?service=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZo", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with query context
			It("Should return StatusBadRequest - Invalid query parameter(context) value given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles?context=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIK", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with query contextContains
			It("Should return StatusBadRequest - Invalid query parameter(contextContains) value given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles?contextContains=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIK", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Request with query allContexts
			It("Should return StatusOK - Valid query parameter(allContexts) given", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931/roles?allContexts=true", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// InternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}/roles", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserRoles, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/roles", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

		})

		// Validate QueryUserPermissions
		Context("Validate QueryUserPermissions", func() {
			// Valid request
			It("Should return StatusOK - Valid request should return roles", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/c80fc308-c388-4f1a-8b6d-53dc1d6d9fca/permissions", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Invalid request StatusUnauthorized
			It("Should return StatusUnauthorized - Insufficient permission provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/c80fc308-c388-4f1a-8b6d-53dc1d6d9fca/permissions", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid request StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/permissions", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
			// Invalid request with Invalid UUID
			It("Should return StatusBadRequest - Invalid UUID provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/690c89f2-b1a0-11ec-b909-0242ac120002/permissions", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid query name
			It("Should return StatusBadRequest - Invalid query paramter(name) value provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/permissions?name=mVYf0dEtkasdasdkdIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUH", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid query service
			It("Should return StatusBadRequest - Invalid query paramter(service) value provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/permissions?service=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZo", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid query context
			It("Should return StatusBadRequest - Invalid query paramter(context) value provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/permissions?context=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIK", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid query contextContains
			It("Should return StatusBadRequest - Invalid query paramter(contextContains) value provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a9/permissions?contextContains=mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIK", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid query allContexts
			It("Should return StatusOK - Valid query paramter(allContexts) value provided", func() {
				router.Handle("/users/{id}/permissions", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.QueryUserPermissions, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/1caea167-7430-4a65-89e7-425776bc2131/permissions?allContexts=true", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleSearch},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

		})

		// Validate GetUserRoleById
		Context("Validate GetUserRoleById", func() {
			// Valid request
			It("Should return StatusOK - Valid request, should return role", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.GetUserRoleById, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Invalid request with invalid user ID
			It("Should return StatusBadRequest - Invalid USER ID provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.GetUserRoleById, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/15edb70e-b1a6-11ec-b909-0242ac120002/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request with invalid role ID
			It("Should return StatusBadRequest - Invalid ROLE ID provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.GetUserRoleById, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/15edba42-b1a6-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid user ID failed to retrieve user
			It("Should return StatusBadRequest - Invalid USER ID provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.GetUserRoleById, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a0/roles/d63d7251-750f-42ae-a443-8987d441f8b6", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid role ID
			It("Should return StatusBadRequest - Invalid ROLE UUID provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.GetUserRoleById, "application/json"))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/d63d7251-750f-42ae-a443-8987d441f8b6", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// Validate DeleteUserRole
		Context("Validate DeleteUserRole", func() {
			// Valid request
			It("Should return StatusNoContent - Valid request, should delete role", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
			// Invalid request Unauthorized
			It("Should return StatusUnauthorized - Insufficient permission provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleRetrieve},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid user UUID
			It("Should return StatusBadRequest - Invalid user UUID", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/dd01f7e8-b1aa-11ec-b909-0242ac120002/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid role UUID
			It("Should return StatusBadRequest - Invalid ROLE UUID", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/dd01fac2-b1aa-11ec-b909-0242ac120002", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request User StatusNotFound
			It("Should return StatusNotFound - Unknown user provided", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/2721edfd-5959-47f6-b517-a0a2d072d58e/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
			// Invalid request User StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/6c8bb11b-e637-48ff-823b-0b3f845785a0/roles/41e56e88-4144-4506-91f7-8d0391e6f04b", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			// Invalid request Role StatusNotFound
			It("Should return StatusNotFound - Unknown ROLE ID given", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/2eeab0ba-d980-4c64-8bda-c416e0319d06", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
			// Invalid request StatusInternalServerError
			It("Should return StatusInternalServerError - To validate DB failure", func() {
				router.Handle("/users/{id}/roles/{role_id}", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.DeleteUserRole, "application/json"))).Methods(http.MethodDelete)

				req, err := http.NewRequest(http.MethodDelete, "/users/1caea167-7430-4a65-89e7-425776bc2131/roles/a7878758-baa7-4c4d-905d-c1ac9e5f0db3", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.UserRoleDelete},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		// Validate ChangePassword
		Context("Validate ChangePassword", func() {
			// Invalid request body
			It("Should return StatusBadRequest - Empty request body", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Valid request
			It("Should return StatusOK - Valid request should change password", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
					"username" : "test_user",
					"old_password" : "testAdminPassword",
					"new_password" : "newTestAdminPassword",
					"password_confirm" : "newTestAdminPassword"
				  }`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
			// Invalid request
			It("Should return StatusBadRequest - Invalid request body provided", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
								"username" : "test_user",
								"old_password : "testAdminPassword",
								"new_password" : "newTestAdminPassword",
								"password_confirm" : "newTestAdminPassword",
							  }`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request invalid username length
			It("Should return StatusUnauthorized - Invalid username provided", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
										"username" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0",
										"old_password" : "testAdminPassword",
										"new_password" : "newTestAdminPassword",
										"password_confirm" : "newTestAdminPassword"
									}`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid request invalid password length
			It("Should return StatusUnauthorized - Invalid password given", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
								"username" : "test_user",
								"old_password" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0",
								"new_password" : "newTestAdminPassword",
								"password_confirm" : "newTestAdminPassword"
							  }`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid request invalid password and password_confirm length
			It("Should return StatusBadRequestnot - Invalid length of password and password_confirm", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
										"username" : "test_user",
										"old_password" : "testAdminPassword",
										"new_password" : "newTestAdminPassword",
										"password_confirm" : "TestAdminPassword"
									}`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
			// Invalid request invalid password length
			It("Should return StatusUnauthorized - Invalid password length", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
										"username" : "test_user",
										"old_password" : "testAdminPassword",
										"new_password" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0",
										"password_confirm" : "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE0"
									}`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid request with invalid old password StatusUnauthorized
			It("Should return StatusUnauthorized - Invalid old password provided", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
								"username" : "test_user",
								"old_password" : "test123AdminPassword",
								"new_password" : "newTestAdminPassword",
								"password_confirm" : "newTestAdminPassword"
							  }`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
			// Invalid request with invalid old password, it should return StatusInternalServerError
			// This validation is used to get simulated DB error in Update method in user store.
			It("Should return StatusInternalServerError - Old password mismatch", func() {
				router.Handle("/users/changepassword", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(userController.ChangePassword, ""))).Methods(http.MethodPatch)

				changePasswordJson := `{
										"username" : "update_user",
										"old_password" : "testAdminPassword",
										"new_password" : "newTestAdminPassword",
										"password_confirm" : "newTestAdminPassword"
									}`

				req, err := http.NewRequest(http.MethodPatch, "/users/changepassword", strings.NewReader(changePasswordJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})
})
