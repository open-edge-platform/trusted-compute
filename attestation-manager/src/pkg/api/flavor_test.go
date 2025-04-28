package api

import (
	"attestation-manager/pkg/constants"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAddFlavorTemplate(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8443",
	}
	token := "test-token"
	hostname := "test-hostname"
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
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	success, message := AddFlavorTemplate(cfg, token, hostname)
	if !success {
		t.Errorf("Expected success, got failure with message: %s", message)
	}
}

func TestGetFlavorIDs(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8443",
	}
	bearerToken := "test-token"
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
		response := FlavorsResponse{
			SignedFlavors: []struct {
				Flavor Flavor `json:"flavor"`
			}{
				{Flavor: Flavor{Meta: struct {
					ID string `json:"id"`
				}{ID: "flavor1"}}},
				{Flavor: Flavor{Meta: struct {
					ID string `json:"id"`
				}{ID: "flavor2"}}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	flavorIDs, err := GetFlavorIDs(cfg, bearerToken)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(flavorIDs) != 2 {
		t.Errorf("Expected 2 flavor IDs, got %d", len(flavorIDs))
	}
}

func TestDeleteFlavor(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8443",
	}
	flavorID := "test-flavor-id"
	bearerToken := "test-token"
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
		w.Write([]byte(`{"status":"deleted"}`))
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	success, message := DeleteFlavor(cfg, flavorID, bearerToken)
	if !success {
		t.Errorf("Expected success, got failure with message: %s", message)
	}
}

func TestGetFlavor(t *testing.T) {
	cfg := &constants.Config{
		HVSURL:  "http://localhost",
		HVSPort: "8443",
	}
	bearerToken := "test-token"
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
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	cfg.HVSURL = server.URL

	success, message := GetFlavor(cfg, bearerToken)
	if !success {
		t.Errorf("Expected success, got failure with message: %s", message)
	}
}
