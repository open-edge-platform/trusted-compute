package api

import (
	"attestation-manager/pkg/constants"
	"net/http"
	"net/http/httptest"
	"strings"
	"os"
	"testing"
)

func TestGenerateTrustReport(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8080",
	}
	token := "dummy_token"
	hostname := "test_host"
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "username")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"reports": [{"id": "1", "trust_information": {"OVERALL": true}}]}`))
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	success, report := GenerateTrustReport(cfg, token, hostname)
	if !success {
		t.Errorf("Expected success, got failure")
	}
	if !strings.Contains(report, `"OVERALL": true`) {
		t.Errorf("Expected report to contain overall trust status, got %s", report)
	}
}

func TestFetchTrustReport(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8080",
	}
	token := "dummy_token"
	hostname := "test_host"
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "username")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"reports": [{"id": "1", "trust_information": {"OVERALL": true}}]}`))
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	success, report := FetchTrustReport(cfg, token, hostname)
	if !success {
		t.Errorf("Expected success, got failure")
	}
	if !strings.Contains(report, `"OVERALL": true`) {
		t.Errorf("Expected report to contain overall trust status, got %s", report)
	}
}

func TestParseTrustReport(t *testing.T) {
	report := `{"reports": [{"id": "1", "trust_information": {"OVERALL": true}, "host_info": {"hardware_uuid": "1234", "hardware_features": {"UEFI": {"enabled": "true", "meta": {"secure_boot_enabled": true}}}}}]}`

	checkTrust, secureBootEnabled, hardwareUUID := ParseTrustReport(report)
	if !checkTrust {
		t.Errorf("Expected trust to be true, got false")
	}
	if !secureBootEnabled {
		t.Errorf("Expected secure boot to be enabled, got disabled")
	}
	if hardwareUUID != "1234" {
		t.Errorf("Expected hardware UUID to be 1234, got %s", hardwareUUID)
	}
}
