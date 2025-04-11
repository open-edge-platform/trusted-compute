/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"crypto"
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
	"github.com/pkg/errors"
)

type DownloadCMSCert struct {
	CaCertDirPath string

	CmsBaseURL    string
	TlsCertDigest string

	ConsoleWriter io.Writer

	commandName string

	Client HttpClient
}

const downloadCMSCertEnvHelpPrompt = "Following environment variables are required for "

var downloadCMSCertEnvHelp = map[string]string{
	"CMS_BASE_URL":        "CMS base URL in the format https://{{cms}}:{{cms_port}}/cms/v1/",
	"CMS_TLS_CERT_SHA384": "SHA384 hash value of CMS TLS certificate",
}

func (cc *DownloadCMSCert) Run() error {
	printToWriter(cc.ConsoleWriter, cc.commandName, "Start downloading CMS CA certificate")
	err := downloadRootCaCertificate(cc.CmsBaseURL, cc.CaCertDirPath, cc.TlsCertDigest, cc.Client)
	if err != nil {
		printToWriter(cc.ConsoleWriter, cc.commandName, "CMS CA certificate download setup failed")
		return err
	}
	return nil
}

func (cc *DownloadCMSCert) Validate() error {
	ok, err := isDirEmpty(cc.CaCertDirPath)
	if err != nil {
		return errors.New("Error opening CMS CA certificate directory")
	}
	if ok == true {
		return errors.New("CMS CA certificate is not downloaded")
	}
	printToWriter(cc.ConsoleWriter, cc.commandName, "CMS CA certificate download setup validated")
	return nil
}

func (t *DownloadCMSCert) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, downloadCMSCertEnvHelpPrompt+t.commandName, "", downloadCMSCertEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *DownloadCMSCert) SetName(n, e string) {
	t.commandName = n
}

func isDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// Client should be passed as nil here.
func downloadRootCaCertificate(cmsBaseUrl string, dirPath string, trustedTlsCertDigest string, client HttpClient) (err error) {
	if !strings.HasSuffix(cmsBaseUrl, "/") {
		cmsBaseUrl = cmsBaseUrl + "/"
	}
	parsedUrl, err := url.Parse(cmsBaseUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to parse CMS URL")
	}
	certificates, _ := parsedUrl.Parse("ca-certificates")
	endpoint := parsedUrl.ResolveReference(certificates)
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to instantiate http request to CMS")
	}
	req.Header.Set("Accept", "application/x-pem-file")
	//InsecureSkipVerify is set to true as connection is validated manually
	if client == nil {
		client = clients.HTTPClientTLSNoVerify()
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to perform HTTP request to CMS")
	}
	defer func() {
		derr := resp.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	// PEM encode the certificate (this is a standard TLS encoding)
	pemBlock := pem.Block{Type: "CERTIFICATE", Bytes: resp.TLS.PeerCertificates[0].Raw}
	certPEM := pem.EncodeToMemory(&pemBlock)
	tlsCertDigest, err := crypt.GetCertHashFromPemInHex(certPEM, crypto.SHA384)
	if err != nil {
		return errors.Wrap(err, "crypt.GetCertHashFromPemInHex failed")
	}
	if resp.StatusCode != http.StatusOK {
		text, _ := ioutil.ReadAll(resp.Body)
		reqErr := fmt.Errorf("Status %d: %s", resp.StatusCode, string(text))
		return errors.Wrap(reqErr, "CMS request failed to download CA Certificate")
	}
	if tlsCertDigest == "" || tlsCertDigest != trustedTlsCertDigest {
		return errors.New("CMS TLS Certificate digest does not match")
	}
	tlsResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to read CMS response body")
	}
	if tlsResp == nil {
		return errors.Wrap(err, "Invalid response from Download CA Certificate")
	}
	err = crypt.SavePemCertWithShortSha1FileName(tlsResp, dirPath)
	if err != nil {
		return errors.Wrap(err, "crypt.SavePemCertWithShortSha1FileName failed")
	}
	return nil
}
