/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres/mock"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	jwtauth "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/jwt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const (
	aasTestDir          = "../../../test/aas/"
	privatekeyLocation  = "../../../test/aas/jwt.key"
	jwtsigncertLocation = "../../../test/aas/jwtsigncert.pem"
)

var (
	testUsers    []types.User
	roles        []types.Role
	permissions  []types.Permission
	passwordHash []byte
	tokenFactory *jwtauth.JwtFactory
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controllers Suite")

	defer func() {
		dirEntry, err := os.ReadDir(aasTestDir)
		assert.NoError(t, err)
		for _, file := range dirEntry {
			// Remove all test files except .gitkeep
			if file.Name() != ".gitkeep" {
				err := os.Remove(filepath.Join(aasTestDir, file.Name()))
				assert.NoError(t, err)
			}
		}
	}()
}

func init() {
	testPassword := "testAdminPassword"
	passwordHash, _ = bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	var err error
	tokenFactory, err = getJWTFactory()
	if tokenFactory == nil || err != nil {
		log.Fatalf("Failed to create JWTTokenFactory %v", err)
	}

	addTestUsers()
	addTestRoles()
	addTestPermissions()

	// create AAS test resource
	createAASTestResource()
}

func createAASTestResource() {
	// create valid test account seed file
	err := ioutil.WriteFile(accountSeedFile, []byte("SAACEOXRSFBL3N2NNUCOC3J4UBPW7NFL7GG6M3HZIZAEQKMLSKTRPYPT7E"), 0600)
	if err != nil {
		log.Fatalf("Error writing AccoutnSeedFile %v", err)
	}
	// create invalid test account seed file with no content
	err = ioutil.WriteFile(emptyAccountSeedFile, nil, 0600)
	if err != nil {
		log.Fatalf("Error writing AccoutnSeedFile %v", err)
	}
}

func createJWTSignCertificate() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	}

	privateKeyFile, err := os.OpenFile(privatekeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := privateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		log.Fatalf("I/O error while encoding private key file %v", err)
	}

	// save certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}
	caPEMFile, err := os.OpenFile(tokenSignCertFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := caPEMFile.Close()
		if derr != nil {
			log.Fatalf("Error while closing file" + derr.Error())
		}
	}()
	err = pem.Encode(caPEMFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		log.Fatalf("Failed to Encode Certificate %v", err)
	}
	return
}

// Adding test requirements for controllers package.
func getJWTFactory() (*jwtauth.JwtFactory, error) {

	createJWTSignCertificate()
	// retrieve the private key from file

	pkcs8Key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(pkcs8Key)
	if err != nil {
		log.Fatalf("Failed to marshal PKCS8 KeyPair %v", err)
	}

	// retrieve the signing key certificate used to create the file
	IncludeKid := true

	var certPemBytes []byte
	if IncludeKid {
		certPemBytes, err = ioutil.ReadFile(jwtsigncertLocation)
		if err != nil {
			return nil, fmt.Errorf("could not read JWT signing certificate file - error : %v", err)
		}
	}

	return jwtauth.NewTokenFactory(keyBytes,
		IncludeKid, certPemBytes,
		"AAS JWT Issuer",
		time.Duration(10)*time.Minute)

}

func getMockUserStore() mock.MockUserStore {
	mockUserStore := mock.MockUserStore{}
	mockUserStore.CreateFunc = func(u types.User) (*types.User, error) {
		// To validate internal server error
		if u.Name == "internalUserError" {
			return nil, errors.New("failed to create user")
		}
		u.ID = uuid.NewString()
		testUsers = append(testUsers, u)
		u.CheckPassword(u.PasswordHash)
		return &u, nil
	}

	mockUserStore.RetrieveFunc = func(u types.User) (*types.User, error) {
		// To validate internal server error
		if u.Name == "internalUserError" {
			return nil, nil
		}
		// To validate internal server error
		if u.ID == "6c8bb11b-e637-48ff-823b-0b3f845785a0" || u.Name == "internalUserError_update" {
			return nil, errors.New("failed to retrieve user")
		}
		// To validate error in existing user validation.
		// User ID is mismatch, validation.
		if u.Name == "test_user_exists" {
			return &types.User{
				ID:           "44a8e1bb-1d9d-44a7-958e-a15352e53103",
				Name:         "test_user_exists",
				PasswordHash: passwordHash,
				PasswordCost: bcrypt.DefaultCost,
			}, nil
		}
		for _, thisUser := range testUsers {
			if u.Name == thisUser.Name || u.ID == thisUser.ID {
				return &thisUser, nil
			}
		}
		return nil, errors.New("record not found")
	}

	mockUserStore.RetrieveAllFunc = func(u types.User) (types.Users, error) {
		// To validate internal server error
		if u.Name == "internalUserError_update" {
			return nil, errors.New("failed to get users")
		}
		var resultUsers types.Users
		for _, user := range testUsers {
			if u.Name == user.Name {
				resultUsers = append(resultUsers, u)
			}
		}
		return resultUsers, nil
	}

	mockUserStore.UpdateFunc = func(u types.User) error {
		// To validate internal server error
		if u.Name == "internalUserError_update" || u.Name == "update_user" {
			return errors.New("failed to update user")
		}

		for index, user := range testUsers {
			if u.ID == user.ID {
				// Update user
				testUsers[index].ID = u.ID
				testUsers[index].CreatedAt = u.CreatedAt
				testUsers[index].UpdatedAt = time.Now()
				testUsers[index].Name = u.Name
				testUsers[index].PasswordHash = u.PasswordHash
				testUsers[index].PasswordSalt = u.PasswordSalt
				testUsers[index].PasswordCost = u.PasswordCost
				testUsers[index].Roles = u.Roles
			}
		}
		return nil
	}

	mockUserStore.DeleteFunc = func(u types.User) error {
		// To validate internal server error
		if u.ID == "6c8bb11b-e637-48ff-823b-0b3f845785a9" {
			return errors.New("failed to delete")
		}
		for index, user := range testUsers {
			if u.ID == user.ID && u.Roles != nil {
				copy(testUsers[index:], testUsers[index+1:])
				testUsers[len(testUsers)-1] = types.User{}
				testUsers = testUsers[:len(testUsers)-1]
				return nil
			}
		}
		return nil
	}

	mockUserStore.UserStore = testUsers
	mockUserStore.RoleStore = roles
	mockUserStore.PermissionStore = permissions

	return mockUserStore
}

func getMockRoleStore() mock.MockRoleStore {
	mockRoleStore := mock.MockRoleStore{}

	mockRoleStore.CreateFunc = func(r types.Role) (*types.Role, error) {
		// To validate internal server error
		if r.Name == "invalid_role" {
			return nil, errors.New("failed to create role")
		}
		roles = append(roles, r)
		return &r, nil
	}

	mockRoleStore.RetrieveFunc = func(rs *types.RoleSearch) (*types.Role, error) {
		for _, role := range roles {
			if role.Name == rs.Name {
				return &role, nil
			}
			for _, id := range rs.IDFilter {
				if role.ID == id {
					return &role, nil
				}
			}
		}
		return nil, errors.New("record not found")
	}

	mockRoleStore.DeleteFunc = func(r types.Role) error {
		// To validate default role
		if r.Name == "Administrator" {
			return errors.New("failed to delete default role")
		}
		// To represent failure in DB. To get InternalServerError
		if r.Name == "test_delete_role1" {
			return errors.New("failed to delete role")
		}
		for _, role := range roles {
			if role.ID == r.ID {
				return nil
			}
		}

		return errors.New("record not found")
	}

	mockRoleStore.RetrieveAllFunc = func(rs *types.RoleSearch) (types.Roles, error) {
		var resultRoles []types.Role
		if rs == nil {
			return roles, nil
		}
		// To validate StatusInternalServerError
		if rs.Name == "invalid_filter" {
			return nil, errors.New("failed to retrieve roles")
		}
		if rs.IDFilter != nil && rs.ServiceFilter != nil || rs.AllContexts {
			for _, role := range roles {
				for _, roleID := range rs.IDFilter {
					if roleID == role.ID {
						resultRoles = append(resultRoles, role)
					}
					// To validate DB failure, BAD_REQUEST should be returned
					// When 'X' number of ROLE(s) is requested and 'Y' number of ROLE(s) are returned.
					if roleID == "de6e6ee5-0369-43f2-9e88-969214cdac1c" {
						return types.Roles{
							{
								ID:       "8ad32e0a-da4f-4344-87d6-f68cee6999e8",
								RoleInfo: aas.RoleInfo{Service: "AAS", Name: "test_delete_role1"},
								Permissions: types.Permissions{
									{
										ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
										Rule: "role:valid",
									},
								},
							},
							{
								ID:       "9bd32e0a-da4f-4344-87d6-f68cee6999e8",
								RoleInfo: aas.RoleInfo{Service: "AAS", Name: "test_delete_role1"},
								Permissions: types.Permissions{
									{
										ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
										Rule: "role:valid",
									},
								},
							},
						}, nil
					}
				}

				for _, svcFltr := range rs.ServiceFilter {
					if svcFltr == role.Service {
						resultRoles = append(resultRoles, role)
					}
				}
			}
			return resultRoles, nil
		}
		for _, role := range roles {
			if role.Name == rs.Name || role.Service == rs.Service ||
				role.Context == rs.Context || strings.Contains(role.Context, rs.ContextContains) {
				resultRoles = append(resultRoles, role)
			}
		}
		if resultRoles != nil {
			return resultRoles, nil
		}
		return types.Roles{}, nil
	}

	return mockRoleStore
}

func getPermissionStore() mock.MockPermissionStore {
	mockPermissionStore := mock.MockPermissionStore{}
	mockPermissionStore.CreateFunc = func(p types.Permission) (*types.Permission, error) {
		// To validate internal server error
		if p.Rule == "rule:InvalidRule" {
			return nil, errors.New("invalid permission requested")
		}
		permissions = append(permissions, p)
		return &p, nil
	}

	mockPermissionStore.RetrieveFunc = func(ps *types.PermissionSearch) (*types.Permission, error) {
		for _, thiPermission := range permissions {
			if thiPermission.Rule == ps.Rule {
				return &thiPermission, nil
			}
		}
		return nil, errors.New("record not found")
	}
	return mockPermissionStore
}

func addTestUsers() {
	// Test Role
	newRole := types.Role{
		ID:        "41e56e88-4144-4506-91f7-8d0391e6f04b",
		CreatedAt: time.Now(),
		RoleInfo:  aas.RoleInfo{Service: "AAS", Name: "GetRoleTest"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}

	// Create test users and add them in global 'testUsers' variable.
	existingUser := types.User{
		ID:           "39ef57fa-76ee-49cd-ae8b-8b9798ac15ab",
		Name:         "existingUser",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        []types.Role{newRole},
	}
	testUsers = append(testUsers, existingUser)

	validUser := types.User{
		ID:           "1caea167-7430-4a65-89e7-425776bc2131",
		Name:         "test_user",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        []types.Role{newRole},
	}
	testUsers = append(testUsers, validUser)

	// To validate internal server error
	updateUser := types.User{
		ID:           "1cama167-7430-4a65-89e7-425776bc2131",
		Name:         "update_user",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        []types.Role{newRole},
	}
	testUsers = append(testUsers, updateUser)

	testUserExists := types.User{
		ID:           "34a8e1bb-1d9d-44a7-958e-a15352e53103",
		Name:         "test_user_exists",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        []types.Role{newRole},
	}
	testUsers = append(testUsers, testUserExists)

	deletedAt := time.Now()
	internalUserErrorUpdate := types.User{
		ID:           "6c8bb11b-e637-48ff-823b-0b3f845785a9",
		Name:         "internalUserError_update",
		DeletedAt:    &deletedAt,
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        nil,
	}
	testUsers = append(testUsers, internalUserErrorUpdate)
	// To validate QueryUserRoles
	queryUserRoles := types.User{
		ID:           "e385c1b1-dca2-4e0a-8cf5-4ea48c1f6931",
		Name:         "queryUserRoles",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles: types.Roles{
			{
				ID:       "8ad32e0a-da4f-4344-87d6-m68cee6999e8",
				RoleInfo: aas.RoleInfo{Service: "AAS", Name: "test_query_role"},
				Permissions: types.Permissions{
					{
						ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
						Rule: "role:valid",
					},
				},
			},
		},
	}
	testUsers = append(testUsers, queryUserRoles)

	// To validate QueryUserRoles
	rolesByID := types.User{
		ID:           "6c8bb11b-e637-48ff-823b-0b3f845785a0",
		Name:         "rolesByID",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        nil,
	}
	testUsers = append(testUsers, rolesByID)

	testUser := types.User{
		ID:           uuid.NewString(),
		Name:         "testusername",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        []types.Role{newRole},
	}
	testUsers = append(testUsers, testUser)

	testUser2 := types.User{
		ID:           uuid.NewString(),
		Name:         "testusername2",
		PasswordHash: passwordHash,
		DeletedAt:    &deletedAt,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        nil,
	}
	testUsers = append(testUsers, testUser2)

	testUser3 := types.User{
		ID:           uuid.NewString(),
		Name:         "testusername3",
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Roles:        nil,
	}
	testUsers = append(testUsers, testUser3)
}

func addTestRoles() {
	// Create test roles and add them in global 'roles' variable.
	testRole := types.Role{
		ID:       "41e56e88-4144-4506-91f7-8d0391e6f04b",
		RoleInfo: aas.RoleInfo{Service: "AAS", Name: "GetRoleTest"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testRole)

	testRole1 := types.Role{
		ID:       "14babd0e-9980-4aa7-a248-3a35a92ff6d4",
		RoleInfo: aas.RoleInfo{Service: "AAS", Name: "test_role1"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testRole1)

	deletedAt := time.Now()
	testRole2 := types.Role{
		ID:        "d63d7251-750f-42ae-a443-8987d441f8b6",
		RoleInfo:  aas.RoleInfo{Service: "AAS", Name: "test_role2"},
		DeletedAt: &deletedAt,
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testRole2)

	testRole3 := types.Role{
		ID:          "a7878758-baa7-4c4d-905d-c1ac9e5f0db3",
		RoleInfo:    aas.RoleInfo{Service: "AAS", Name: "test_role3"},
		DeletedAt:   &deletedAt,
		Permissions: nil,
	}
	roles = append(roles, testRole3)

	testDeleteRole := types.Role{
		ID:       "b860c076-0d96-45c2-bd3e-d63eb9f84e12",
		RoleInfo: aas.RoleInfo{Service: "AAS", Name: "GetRoleTest"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testDeleteRole)

	// Default role
	testDefaultRole := types.Role{
		ID:       "c33deb88-e3f0-423a-a150-525991460c74",
		RoleInfo: aas.RoleInfo{Service: "AAS", Name: "Administrator"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testDefaultRole)
	// To validate internal server error
	testDeleteRole1 := types.Role{
		ID:       "8bd32e0a-da4f-4344-87d6-f68cee6999e8",
		RoleInfo: aas.RoleInfo{Service: "AAS", Name: "test_delete_role1"},
		Permissions: types.Permissions{
			{
				ID:   "ab2941b9-30db-475d-86aa-099c8ca1aee1",
				Rule: "role:valid",
			},
		},
	}
	roles = append(roles, testDeleteRole1)
}

func addTestPermissions() {
	// Create test permissions and add them in global 'permissions' variable.
	testPermission := types.Permission{
		ID:   "c80fc308-c388-4f1a-8b6d-53dc1d6d9fca",
		Rule: "test:testRule",
	}

	permissions = append(permissions, testPermission)

	internalErrorPermission := types.Permission{
		ID:   "14cc6386-0a26-4ba0-bfea-1df8791c0659",
		Rule: "test:invalid",
	}

	permissions = append(permissions, internalErrorPermission)
}
