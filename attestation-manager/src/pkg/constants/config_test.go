/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

import (
	"os"
	"testing"
)

// helper to set and unset env vars for each test
func withEnv(env map[string]string, fn func()) {
	originals := make(map[string]string)
	for k, v := range env {
		originals[k] = os.Getenv(k)
		os.Setenv(k, v)
	}
	fn()
	for k, v := range originals {
		os.Setenv(k, v)
	}
	// Unset any env vars that were set in env but not present in originals (i.e., were not set before)
	for k := range env {
		if _, ok := originals[k]; !ok {
			os.Unsetenv(k)
		}
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"AAS_URL":                            "https://aas.example.com",
		"AAS_PORT":                           "8443",
		"AAS_USERNAME":                       "testuser",
		"AAS_PASSWORD":                       "testpass",
		"CMS_URL":                            "https://cms.example.com",
		"CMS_PORT":                           "8444",
		"HVS_URL":                            "https://hvs.example.com",
		"HVS_PORT":                           "8445",
		"HOSTNAME":                           "testhost",
		"TCHOSTNAME":                         "tchost",
		"POLL_DURATION":                      "30",
		"Attestation_Manager_SERVER_PORT":    "8080",
		"Attestation_Manager_SERVER_ADDRESS": "http://localhost",
	}
}

func TestLoadConfig_Success(t *testing.T) {
	env := validEnv()
	withEnv(env, func() {
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.AASURL != env["AAS_URL"] {
			t.Errorf("AASURL mismatch: got %s, want %s", cfg.AASURL, env["AAS_URL"])
		}
		if cfg.CMSURL != env["CMS_URL"] {
			t.Errorf("CMSURL mismatch: got %s, want %s", cfg.CMSURL, env["CMS_URL"])
		}
		// Check other fields
		if cfg.AASPort != env["AAS_PORT"] {
			t.Errorf("AASPort mismatch: got %s, want %s", cfg.AASPort, env["AAS_PORT"])
		}
		if cfg.AASUsername != env["AAS_USERNAME"] {
			t.Errorf("AASUsername mismatch: got %s, want %s", cfg.AASUsername, env["AAS_USERNAME"])
		}
		if cfg.AASPassword != env["AAS_PASSWORD"] {
			t.Errorf("AASPassword mismatch: got %s, want %s", cfg.AASPassword, env["AAS_PASSWORD"])
		}
		if cfg.CMSPort != env["CMS_PORT"] {
			t.Errorf("CMSPort mismatch: got %s, want %s", cfg.CMSPort, env["CMS_PORT"])
		}
		if cfg.HVSURL != env["HVS_URL"] {
			t.Errorf("HVSURL mismatch: got %s, want %s", cfg.HVSURL, env["HVS_URL"])
		}
		if cfg.HVSPort != env["HVS_PORT"] {
			t.Errorf("HVSPort mismatch: got %s, want %s", cfg.HVSPort, env["HVS_PORT"])
		}
		if cfg.HOSTNAME != env["HOSTNAME"] {
			t.Errorf("HOSTNAME mismatch: got %s, want %s", cfg.HOSTNAME, env["HOSTNAME"])
		}
		if cfg.TCHOSTNAME != env["TCHOSTNAME"] {
			t.Errorf("TCHOSTNAME mismatch: got %s, want %s", cfg.TCHOSTNAME, env["TCHOSTNAME"])
		}
		if cfg.AttestationManagerServerAddress != env["Attestation_Manager_SERVER_ADDRESS"] {
			t.Errorf("AttestationManagerServerAddress mismatch: got %s, want %s", cfg.AttestationManagerServerAddress, env["Attestation_Manager_SERVER_ADDRESS"])
		}
		if cfg.AttestationManagerServerPort != env["Attestation_Manager_SERVER_PORT"] {
			t.Errorf("AttestationManagerServerPort mismatch: got %s, want %s", cfg.AttestationManagerServerPort, env["Attestation_Manager_SERVER_PORT"])
		}
		// Check POLLDURATION
		if cfg.POLLDURATION != 30 {
			t.Errorf("POLLDURATION mismatch: got %d, want 30", cfg.POLLDURATION)
		}
		// Check default paths
		if cfg.NodeAgentCertPath != "/mnt/access_token" {
			t.Errorf("NodeAgentCertPath default mismatch")
		}
	})
}

func TestLoadConfig_MissingRequiredEnv(t *testing.T) {
	env := validEnv()
	delete(env, "AAS_URL")
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for missing AAS_URL, got nil")
		}
	})
}

func TestLoadConfig_MissingPollDuration(t *testing.T) {
	env := validEnv()
	delete(env, "POLL_DURATION")
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for missing POLL_DURATION, got nil")
		}
	})
}

func TestLoadConfig_InvalidPollDuration(t *testing.T) {
	env := validEnv()
	env["POLL_DURATION"] = "notanint"
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for invalid POLL_DURATION, got nil")
		}
	})
}

func TestLoadConfig_InvalidURL(t *testing.T) {
	env := validEnv()
	env["AAS_URL"] = "http://notsecure.com"
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for invalid AAS_URL, got nil")
		}
	})
}

func TestLoadConfig_InvalidPort(t *testing.T) {
	env := validEnv()
	env["AAS_PORT"] = "7000" // below 8000
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for invalid AAS_PORT, got nil")
		}
	})
	env = validEnv()
	env["AAS_PORT"] = "notaport"
	withEnv(env, func() {
		_, err := LoadConfig()
		if err == nil || err.Error() == "" {
			t.Fatal("expected error for non-integer AAS_PORT, got nil")
		}
	})
}

func TestLoadConfig_OptionalServerAddress(t *testing.T) {
	env := validEnv()
	env["Attestation_Manager_SERVER_ADDRESS"] = "test1234"
	// Do not set Attestation_Manager_SERVER_ADDRESS
	withEnv(env, func() {
		_, err := LoadConfig()
		if err != nil {
			t.Fatalf("expected no error when Attestation_Manager_SERVER_ADDRESS is missing, got %v", err)
		}
	})
}
