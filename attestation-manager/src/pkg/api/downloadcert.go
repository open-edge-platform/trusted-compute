/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

var (
	httpClient *http.Client
	once       sync.Once
)

// retryOperation retries the given operation function up to retryCount times with a delay of retryInterval between attempts.
func retryOperation(operation func() (bool, error), retryCount int, retryInterval time.Duration) (bool, error) {
	for i := 0; i < retryCount; i++ {
		success, err := operation()
		if success {
			return true, nil
		}
		if i < retryCount-1 {
			logging.Info(fmt.Sprintf("Retrying operation in %v seconds...", retryInterval.Seconds()))
			time.Sleep(retryInterval)
		} else {
			logging.Error("Exceeded maximum retries for operation")
			return false, err
		}
	}
	return false, nil
}

// downloadCACertificate downloads the CA certificate from the given URL and saves it to the specified path.
func downloadCACertificate(url, outputPath string) error {

	retryCount := 10
	retryInterval := 60 * time.Second

	operation := func() (bool, error) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logging.Error("Error creating the request: ", err)
			return false, err
		}

		req.Header.Set("Accept", "application/x-pem-file")

		resp, err := client.Do(req)
		if err != nil {
			logging.Error("Error making the request: ", err)
			return false, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			logging.Error("Failed to download CA certificate, status code: ", resp.StatusCode)
			return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logging.Error("Error reading the response body: ", err)
			return false, err
		}

		// Write the response body to the specified file
		err = os.WriteFile(outputPath, body, 0644)
		if err != nil {
			logging.Error("Error writing the CA certificate to file: ", err)
			return false, err
		}

		return true, nil
	}

	_, err := retryOperation(operation, retryCount, retryInterval)
	return err
}

// HTTPClientWithCA creates an HTTP client that uses the CA certificate at the specified path.
func initHTTPClient() {
	cfg, err := constants.LoadConfig()
	if err != nil {
		logging.Error(fmt.Sprintf("Error loading configuration: %v", err))
	}
	caCertPath := "/app/ca-certificate.pem"
	caCertURL := fmt.Sprintf("%s:%s/cms/v1/ca-certificates", cfg.CMSURL, cfg.CMSPort)

	if err := downloadCACertificate(caCertURL, caCertPath); err != nil {
		logging.Error("Error downloading CA certificate: ", err)
		return
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		logging.Error("Error reading CA certificate:", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func HTTPClientWithCA() (*http.Client, error) {
	once.Do(initHTTPClient)
	if httpClient == nil {
		logging.Error("Failed to initialize HTTP client")
		return nil, fmt.Errorf("HTTP client initialization failed")
	}
	return httpClient, nil
}
