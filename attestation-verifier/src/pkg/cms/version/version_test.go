package version

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	serviceName := "Service Name: Certificate Management Service"
	if !strings.Contains(version, serviceName) {
		t.Errorf("Service name cms should be returned")
	}
}
