/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	log "github.com/sirupsen/logrus"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

type DownloadCert struct {
	KeyFile       string
	CertFile      string
	KeyAlgorithm  string
	KeyLength     int
	Subject       pkix.Name
	SanList       string
	CertType      string
	CaCertDirPath string
	Client        HttpClient

	CmsBaseURL  string
	BearerToken string

	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

const downloadCAEnvHelpPrompt = "Following environment variables are optionally used in "

var downloadCAEnvCommonHelp = map[string]string{
	"CERT_FILE":   "The file to which certificate is saved",
	"KEY_FILE":    "The file to which private key is saved",
	"COMMON_NAME": "The common name of signed certificate",
}

var downloadTlsCAEnvHelp = map[string]string{
	"SAN_LIST": "Comma separated list of hostnames to add to Certificate, including IP addresses and DNS names",
}

var downloadSamlCAEnvHelp = map[string]string{
	"ISSUER":           "The issuer of signed certificate",
	"VALIDITY_SECONDS": "The validity time in seconds of signed certificate",
}

const downloadCAEnvHelpPrompt2 = "Following environment variables are required in "

var downloadCAEnvHelp2 = map[string]string{
	"CMS_BASE_URL": "CMS base URL in the format https://{{cms}}:{{cms_port}}/cms/v1/",
	"BEARER_TOKEN": "Bearer token for accessing CMS api",
}

func (dc *DownloadCert) Run() error {
	if dc.CmsBaseURL == "" {
		return errors.New("CMS_BASE_URL is not set")
	}
	if dc.BearerToken == "" {
		return errors.New("BEARER_TOKEN is not set")
	}
	// validate host names
	// this should be moved to crypt.CreateKeyPairAndCertificateRequest
	// or change crypt.CreateKeyPairAndCertificateRequest that it takes in hosts as slice of strings
	if dc.SanList != "" {
		hosts := strings.Split(dc.SanList, ",")
		for _, h := range hosts {
			valid_err := validation.ValidateHostname(h)
			if valid_err != nil {
				return errors.Wrap(valid_err, "Failed to validate hostname or ip")
			}
		}
	}
	printToWriter(dc.ConsoleWriter, dc.commandName, "Start downloading certificate")
	key, cert, err := getCertificateFromCMS(dc.CertType, dc.KeyAlgorithm, dc.KeyLength, dc.CmsBaseURL, dc.Subject, dc.SanList, dc.CaCertDirPath, dc.BearerToken, dc.Client)
	if err != nil {
		printToWriter(dc.ConsoleWriter, dc.commandName, "Failed to download certificate")
		return err
	}
	err = crypt.SavePrivateKeyAsPKCS8(key, dc.KeyFile)
	if err != nil {
		return errors.Wrap(err, "crypt.SavePrivateKeyAsPKCS8 failed")
	}

	fi, err := os.Stat(dc.CertFile)
	if err != nil || fi.Mode().IsRegular() {
		err = ioutil.WriteFile(dc.CertFile, cert, 0600)
		if err != nil {
			printToWriter(dc.ConsoleWriter, dc.commandName, "Failed to save certificate")
			return errors.Wrap(err, "Could not store Certificate")
		}
		err = os.Chmod(dc.CertFile, 0600)
		if err != nil {
			printToWriter(dc.ConsoleWriter, dc.commandName, "Failed to change file permission")
			return errors.Wrap(err, "Could not change file permission")
		}
	} else if fi.Mode().IsDir() {
		err = crypt.SavePemCertWithShortSha1FileName(cert, dc.CertFile)
		if err != nil {
			printToWriter(dc.ConsoleWriter, dc.commandName, "Failed to save certificate")
			return errors.Wrap(err, "Could not store Certificate")
		}
	}
	printToWriter(dc.ConsoleWriter, dc.commandName, "Certificate downloaded")
	return nil
}

func (dc *DownloadCert) Validate() error {
	_, err := os.Stat(dc.KeyFile)
	if os.IsNotExist(err) {
		return errors.New("KeyFile is not configured")
	}
	printToWriter(dc.ConsoleWriter, dc.commandName, "Certificate download setup validated")
	return nil
}

func (t *DownloadCert) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, downloadCAEnvHelpPrompt2+t.commandName, "", downloadCAEnvHelp2)
	if t.commandName == "download-cert-tls" {
		PrintEnvHelp(w, "", t.envPrefix, downloadTlsCAEnvHelp)
		fmt.Fprintln(w, "")
		PrintEnvHelp(w, downloadCAEnvHelpPrompt+t.commandName, t.envPrefix, downloadCAEnvCommonHelp)
	} else if t.commandName == "download-cert-saml" {
		PrintEnvHelp(w, downloadCAEnvHelpPrompt+t.commandName, t.envPrefix, downloadCAEnvCommonHelp)
		PrintEnvHelp(w, "", t.envPrefix, downloadSamlCAEnvHelp)
	} else {
		PrintEnvHelp(w, downloadCAEnvHelpPrompt+t.commandName, t.envPrefix, downloadCAEnvCommonHelp)
	}
	fmt.Fprintln(w, "")
}

func (t *DownloadCert) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = PrefixUnderscroll(e)
}

func getCertificateFromCMS(certType string, keyAlg string, keyLen int, cmsBaseUrl string, subject pkix.Name, hosts string, CaCertDirPath string, bearerToken string, client HttpClient) (key []byte, cert []byte, err error) {
	//TODO: use CertType for TLS or Signing cert
	csrData, key, err := crypt.CreateKeyPairAndCertificateRequest(subject, hosts, keyAlg, keyLen)
	if err != nil {
		return nil, nil, errors.Wrap(err, "crypt.CreateKeyPairAndCertificateRequest failed")
	}
	if !strings.HasSuffix(cmsBaseUrl, "/") {
		cmsBaseUrl = cmsBaseUrl + "/"
	}
	url, err := url.Parse(cmsBaseUrl)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse CMS URL")
	}
	certificates, _ := url.Parse("certificates?certType=" + certType)
	endpoint := url.ResolveReference(certificates)
	csrPemBytes := pem.EncodeToMemory(&pem.Block{Type: "BEGIN CERTIFICATE REQUEST", Bytes: csrData})
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(csrPemBytes))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to instantiate http request to CMS")
	}
	req.Header.Set("Accept", "application/x-pem-file")
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	caCerts, err := crypt.GetCertsFromDir(CaCertDirPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to read CA Certs")
	}

	if client == nil {
		client, err = clients.HTTPClientWithCA(caCerts)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Failed create http client")
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to perform HTTP request to CMS")
	}
	defer func() {
		derr := resp.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		text, _ := ioutil.ReadAll(resp.Body)
		reqErr := fmt.Errorf("Status %d: %s", resp.StatusCode, string(text))
		return nil, nil, errors.Wrap(reqErr, "CMS request failed to download Certificate")
	}
	cert, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to read CMS response body")
	}
	return
}
