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
	// Do not set Attestation_Manager_SERVER_ADDRESS
	withEnv(env, func() {
		_, err := LoadConfig()
		if err != nil {
			t.Fatalf("expected no error when Attestation_Manager_SERVER_ADDRESS is missing, got %v", err)
		}
	})
}
