package api

import (
	"attestation-manager/pkg/constants"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

// Test-specific function to simulate loading configuration
func loadTestConfig() *constants.Config {
	return &constants.Config{
		AASURL:                          "http://example.com",
		AASPort:                         "1234",
		AASUsername:                     "testuser",
		AASPassword:                     "testpassword",
		CMSURL:                          "http://cms.example.com",
		CMSPort:                         "5678",
		HVSURL:                          "http://hvs.example.com",
		HVSPort:                         "9101",
		AttestationManagerServerAddress: "http://attestation-manager.example.com",
		CMSCertPath:                     "test-ca-cert.pem", // Ensure this matches the file created
	}
}

func TestHTTPClientWithCA(t *testing.T) {
	// Mock the CA certificate file
	caCertContent := []byte("test-ca-cert")
	err := os.WriteFile("test-ca-cert.pem", caCertContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write CA cert file: %v", err)
	}
	defer os.Remove("test-ca-cert.pem")

	// Use the test-specific configuration loader
	cfg := loadTestConfig()

	// Create the HTTP client using the test configuration
	client, err := createHTTPClientWithCA(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if client == nil {
		t.Fatalf("Expected HTTP client, got nil")
	}

	// Verify the HTTP client configuration
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected *http.Transport, got %T", client.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatalf("Expected TLSClientConfig, got nil")
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("Expected RootCAs, got nil")
	}
}

// Helper function to create an HTTP client with CA
func createHTTPClientWithCA(cfg *constants.Config) (*http.Client, error) {
	caCert, err := ioutil.ReadFile(cfg.CMSCertPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	return client, nil
}