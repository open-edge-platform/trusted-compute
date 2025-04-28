// package api
package api

import (
	"attestation-manager/pkg/constants"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestGetAttestToken(t *testing.T) {
	// Set up environment variables
	os.Setenv("AAS_URL", "http://example.com")
	os.Setenv("AAS_PORT", "1234")
	os.Setenv("AAS_USERNAME", "testuser")
	os.Setenv("AAS_PASSWORD", "testpassword")
	os.Setenv("CMS_URL", "http://cms.example.com")
	os.Setenv("CMS_PORT", "5678")
	os.Setenv("HVS_URL", "http://hvs.example.com")
	os.Setenv("HVS_PORT", "9101")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager.example.com")
	defer os.Unsetenv("AAS_URL")
	defer os.Unsetenv("AAS_PORT")
	defer os.Unsetenv("AAS_USERNAME")
	defer os.Unsetenv("AAS_PASSWORD")
	defer os.Unsetenv("CMS_URL")
	defer os.Unsetenv("CMS_PORT")
	defer os.Unsetenv("HVS_URL")
	defer os.Unsetenv("HVS_PORT")
	defer os.Unsetenv("Attestation_Manager_SERVER_ADDRESS")

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mocked_token"))
	}))
	defer server.Close()

	// Load configuration
	cfg, err := constants.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Override the AASURL to point to the mock server
	cfg.AASURL = server.URL

	// Test case
	success, token := GetAttestToken(cfg)
	if !success {
		t.Errorf("Expected success to be true, got false")
	}
	if token != "mocked_token" {
		t.Errorf("Expected token to be 'mocked_token', got %s", token)
	}
}
// import (
// 	"attestation-manager/pkg/constants"
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"
// )

// // func mockLoadConfig() *constants.Config {
// // 	return &constants.Config{
// 		// AASURL:                          "http://example.com",
// 		// AASPort:                         "1234",
// 		// AASUsername:                     "testuser",
// 		// AASPassword:                     "testpassword",
// 		// CMSURL:                          "http://cms.example.com",
// 		// CMSPort:                         "5678",
// 		// HVSURL:                          "http://hvs.example.com",
// 		// HVSPort:                         "9101",
// 		// AttestationManagerServerAddress: "http://attestation-manager.example.com",
// // 	}
// // }
// // Test-specific function to simulate loading configuration
// func loadTokenTestConfig() *constants.Config {
// 	return &constants.Config{
// 		// CMSCertPath: "test-ca-cert.pem",
// 		// CMSURL:      "http://localhost",
// 		// CMSPort:     "8080",
// 		AASURL:                          "http://example.com",
// 		AASPort:                         "1234",
// 		AASUsername:                     "testuser",
// 		AASPassword:                     "testpassword",
// 		CMSURL:                          "http://cms.example.com",
// 		CMSPort:                         "5678",
// 		HVSURL:                          "http://hvs.example.com",
// 		HVSPort:                         "9101",
// 		AttestationManagerServerAddress: "http://attestation-manager.example.com",
// 	}
// }

// func TestGetAttestToken(t *testing.T) {
// 	// Mock HTTP server
// 	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte("mocked_token"))
// 	}))
// 	defer server.Close()

// 	// Use the test-specific configuration
// 	cfg := loadTokenTestConfig()
// 	// cfg.AASURL = server.URL // Override the URL to point to the mock server

// 	// Test case
// 	success, token := GetAttestToken(cfg)
// 	if !success {
// 		t.Errorf("Expected success to be true, got false")
// 	}
// 	if token != "mocked_token" {
// 		t.Errorf("Expected token to be 'mocked_token', got %s", token)
// 	}
// }

// func getTestConfig() *constants.Config {
// 	return mockLoadConfig()
// }

// func mockLoadConfig() *constants.Config {
// 	panic("unimplemented")
// }
// // func TestGetAttestToken(t *testing.T) {
// // 	// Mock HTTP server
// // 	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		w.WriteHeader(http.StatusOK)
// // 		w.Write([]byte("mocked_token"))
// // 	}))
// // 	defer server.Close()

// // 	// Mock configuration
// // 	cfg := mockLoadConfig()
// // 	cfg.AASURL = server.URL

// // 	// Test case
// // 	success, token := GetAttestToken(cfg)
// // 	if !success {
// // 		t.Errorf("Expected success to be true, got false")
// // 	}
// // 	if token != "mocked_token" {
// // 		t.Errorf("Expected token to be 'mocked_token', got %s", token)
// // 	}
// // }
