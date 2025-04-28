package main

import (
	
	"attestation-manager/pkg/constants"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"os"
)

func TestRunAttestationManager(t *testing.T) {
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "username")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")

	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8080",
	}
	token := "dummy_token"
	hostName := "test_host"

	// Mock server to simulate API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hvs/v2/reports":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"reports": [{"id": "1", "trust_information": {"OVERALL": true}}]}`))
		case "/hvs/v2/hosts":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"hosts": [{"id": "1", "name": "test_host"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	// Run the attestation manager logic
	go RunAttestationManager(cfg, token, hostName)

	// Allow some time for the logic to execute
	time.Sleep(2 * time.Second)

	// Add assertions here to verify the expected behavior
	// For example, you can check logs or mock server requests
}