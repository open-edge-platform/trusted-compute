package api

import (
	"attestation-manager/pkg/constants"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAddHostToVerifier(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8080",
	}
	token := "test-token"
	hostname := "test-host"
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "username")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")


	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected 'POST' request, got '%s'", r.Method)
		}
		if r.URL.EscapedPath() != "/hvs/v2/hosts" {
			t.Errorf("Expected request to '/hvs/v2/hosts', got '%s'", r.URL.EscapedPath())
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "success"}`))
	}))
	defer ts.Close()

	cfg.HVSURL = ts.URL

	success, response := AddHostToVerifier(cfg, token, hostname)
	if !success {
		t.Errorf("Expected success, got failure")
	}
	if response != `{"result": "success"}` {
		t.Errorf("Expected response to be '%s', got '%s'", `{"result": "success"}`, response)
	}
}

func TestFetchHosts(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8080",
	}
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "username")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")

	token := "test-token"

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected 'GET' request, got '%s'", r.Method)
		}
		if r.URL.EscapedPath() != "/hvs/v2/hosts" {
			t.Errorf("Expected request to '/hvs/v2/hosts', got '%s'", r.URL.EscapedPath())
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"host_name": "test-host"}]`))
	}))
	defer ts.Close()

	cfg.HVSURL = ts.URL

	success, response := FetchHosts(cfg, token)
	if !success {
		t.Errorf("Expected success, got failure")
	}
	expectedResponse := `[{"host_name": "test-host"}]`
	if response != expectedResponse {
		t.Errorf("Expected response to be '%s', got '%s'", expectedResponse, response)
	}
}
