/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Helper to create a JWT string with a custom "iss" claim
func createTestJWT(issuer string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer,
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return tokenString
}

// Helper to write a JWT string to a temp file and return the path
func writeJWTToTempFile(t *testing.T, jwtStr string) string {
	tmpFile, err := os.CreateTemp(os.TempDir(), "jwt_test_*.jwt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()
	_, err = tmpFile.WriteString(jwtStr)
	if err != nil {
		t.Fatalf("Failed to write JWT to temp file: %v", err)
	}
	return tmpFile.Name()
}

func TestExtractJwtPayloadData_KeycloakIssuer(t *testing.T) {
	issuer := "https://example.com/keycloak/realm"
	jwtStr := createTestJWT(issuer)
	filePath := writeJWTToTempFile(t, jwtStr)
	defer os.Remove(filePath)

	result := extractJwtPayloadData(filePath)
	//expected := strings.Replace("keycloak", "keycloak", "attest-node", 1) // "attest-node"
	//log expected	string
	//t.Logf("Expected: %q", expected)

	if result != "example.com" {
		t.Errorf("Expected %q, got %q", "attest-node", result)
	}
}

func TestExtractJwtPayloadData_NonKeycloakIssuer(t *testing.T) {
	issuer := "https://example.com/other/realm"
	jwtStr := createTestJWT(issuer)
	filePath := writeJWTToTempFile(t, jwtStr)
	defer os.Remove(filePath)

	result := extractJwtPayloadData(filePath)
	expected := "example.com"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestExtractJwtPayloadData_InvalidFile(t *testing.T) {
	invalidPath := filepath.Join(os.TempDir(), "jwt_test_invalid.jwt")
	result := extractJwtPayloadData(invalidPath)
	if result != "" {
		t.Errorf("Expected empty string for invalid file, got %q", result)
	}
}

func TestExtractJwtPayloadData_NoIssuer(t *testing.T) {
	// JWT without "iss" claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test",
	})
	jwtStr, _ := token.SignedString([]byte("test-secret"))
	filePath := writeJWTToTempFile(t, jwtStr)
	defer os.Remove(filePath)

	result := extractJwtPayloadData(filePath)
	if result != "" {
		t.Errorf("Expected empty string when 'iss' claim is missing, got %q", result)
	}
}

func TestExtractJwtPayloadData_ShortIssuer(t *testing.T) {
	issuer := "short"
	jwtStr := createTestJWT(issuer)
	filePath := writeJWTToTempFile(t, jwtStr)
	defer os.Remove(filePath)

	result := extractJwtPayloadData(filePath)
	if result != "" {
		t.Errorf("Expected empty string for short issuer, got %q", result)
	}
}
