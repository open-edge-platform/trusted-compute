
package constants

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Set up environment variables for testing
	os.Setenv("AAS_URL", "http://aas-url")
	os.Setenv("AAS_PORT", "8444")
	os.Setenv("AAS_USERNAME", "admin")
	os.Setenv("AAS_PASSWORD", "password")
	os.Setenv("CMS_URL", "http://cms-url")
	os.Setenv("CMS_PORT", "8445")
	os.Setenv("HVS_URL", "http://hvs-url")
	os.Setenv("HVS_PORT", "8446")
	os.Setenv("Attestation_Manager_SERVER_ADDRESS", "http://attestation-manager")

	// Clean up environment variables after test
	defer func() {
		os.Unsetenv("AAS_URL")
		os.Unsetenv("AAS_PORT")
		os.Unsetenv("AAS_USERNAME")
		os.Unsetenv("AAS_PASSWORD")
		os.Unsetenv("CMS_URL")
		os.Unsetenv("CMS_PORT")
		os.Unsetenv("HVS_URL")
		os.Unsetenv("HVS_PORT")
		os.Unsetenv("Attestation_Manager_SERVER_ADDRESS")
	}()

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if config.AASURL != "http://aas-url" {
		t.Errorf("Expected AASURL to be 'http://aas-url', got %v", config.AASURL)
	}
	if config.AASPort != "8444" {
		t.Errorf("Expected AASPort to be '8444', got %v", config.AASPort)
	}
	if config.AASUsername != "admin" {
		t.Errorf("Expected AASUsername to be 'admin', got %v", config.AASUsername)
	}
	if config.AASPassword != "password" {
		t.Errorf("Expected AASPassword to be 'password', got %v", config.AASPassword)
	}
	if config.CMSURL != "http://cms-url" {
		t.Errorf("Expected CMSURL to be 'http://cms-url', got %v", config.CMSURL)
	}
	if config.CMSPort != "8445" {
		t.Errorf("Expected CMSPort to be '8445', got %v", config.CMSPort)
	}
	if config.HVSURL != "http://hvs-url" {
		t.Errorf("Expected HVSURL to be 'http://hvs-url', got %v", config.HVSURL)
	}
	if config.HVSPort != "8446" {
		t.Errorf("Expected HVSPort to be '8446', got %v", config.HVSPort)
	}
	if config.AttestationManagerServerAddress != "http://attestation-manager" {
		t.Errorf("Expected AttestationManagerServerAddress to be 'http://attestation-manager', got %v", config.AttestationManagerServerAddress)
	}
}

func TestLoadConfigMissingVars(t *testing.T) {
	// Ensure no environment variables are set
	os.Clearenv()

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("Expected an error due to missing environment variables, got none")
	}
}
