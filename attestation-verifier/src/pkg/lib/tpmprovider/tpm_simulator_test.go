/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"time"
)

const (
	TPM_SERVER                 = "tpm_server"
	DEFAULT_SLEEP_MILLISECONDS = 500 * time.Millisecond
	MAX_ATTEMPTS               = 5
	TPM_SIMULATOR_EK           = 0x810180a0
	TPM_SIMULATOR_PATH         = "/usr/bin/tpm_server"
	TPM2_STARTUP               = "/usr/bin/tpm2_startup"
)

//
// The TpmSimulator wraps the MS simulator (installed at /simulator on 'gtpm-devel'
// container) so that unit tests can be integrated into cicd pipelines.
//
// Manually, you would run '/simulator/src/tpm_server -rm&' to start the simulator
// in the background, run "tpm2_startup -c -T mssim:host=localhost,port=2321", and run
// tpm2-tools or tpm-provider unit tests usng the 'mssim' tcti.
//
// This class attempts to automate that process with sleeps that make sure
// the simulator is initiated for unit tests in 'tpmprovider_test.go'.
//
type TpmSimulator interface {
	IsRunning() bool
	Start() error
	Stop() error
	ProvisionEkCertificate(tpmProvider TpmProvider, ownerSecretKey, endorsementSecretKey string) error
}

type tpmSimulator struct {
	simulatorCmd *exec.Cmd
}

func NewTpmSimulator() TpmSimulator {
	return &tpmSimulator{}
}

func (simulator *tpmSimulator) IsRunning() bool {
	return simulator.simulatorCmd != nil
}

func (simulator *tpmSimulator) Start() error {

	if _, err := os.Stat(TPM2_STARTUP); os.IsNotExist(err) {
		return fmt.Errorf("TPM2-Tools is required to run the simulator, could not find %s", TPM2_STARTUP)
	}

	if _, err := os.Stat(TPM_SIMULATOR_PATH); os.IsNotExist(err) {
		return fmt.Errorf("The TPM simulator is not present at %s", TPM_SIMULATOR_PATH)
	}

	// requires simulator scripts in /docker-devel image...
	simulator.simulatorCmd = exec.Command(TPM_SIMULATOR_PATH, "-rm") // -rm forces the removal of NVChip to reset the TPM simulator

	// start-tpm-simulator spawns tpm_server in the background, wait for the script to finish
	err := simulator.simulatorCmd.Start()
	if err != nil {
		return fmt.Errorf("There was an error starting the tpm_server: %w", err)
	}

	// give the simulator some time to startup
	time.Sleep(DEFAULT_SLEEP_MILLISECONDS * 3)

	// run tpm2_startup against the simulator (this is needed for the tss2 to work with mssim tcti)
	tpm2StartupCmd := exec.Command(TPM2_STARTUP, "-c", "-T", "mssim:host=localhost,port=2321")
	err = tpm2StartupCmd.Run()
	if err != nil {
		simulator.Stop()
		return fmt.Errorf("Failed to run %s, the TPM simulator has been stopped: %w", TPM2_STARTUP, err)
	}

	fmt.Printf("TPM Simulator started: %d\n", simulator.simulatorCmd.Process.Pid)
	return nil
}

func (simulator *tpmSimulator) Stop() error {

	if simulator.simulatorCmd != nil {
		pid := simulator.simulatorCmd.Process.Pid
		simulator.simulatorCmd.Process.Kill()
		simulator.simulatorCmd = nil
		time.Sleep(DEFAULT_SLEEP_MILLISECONDS * 2)
		fmt.Printf("Stopped TPM Simulator with pid %d\n", pid)
	} else {
		fmt.Printf("The simulator is not running and can't be stopped")
	}

	return nil
}

func (simulator *tpmSimulator) ProvisionEkCertificate(tpmProvider TpmProvider, ownerSecretKey, endorsementSecretKey string) error {

	if !simulator.IsRunning() {
		return errors.New("TpmSimulator.Start must be called before ProvisionEkCertificate")
	}

	//
	// Throw an error if the TPM is not already owned by "ownerSecretKey"
	//
	isOwned, err := tpmProvider.IsOwnedWithAuth(ownerSecretKey)
	if err != nil {
		return err
	}

	if !isOwned {
		return errors.New("The owner secret key is not valid.  Hint: tpmprovider.TakeOwnership must be called before ProvisionEkCertificate")
	}

	//
	// We need a public key from the TPM.  Create an EK at an unused handle and get it's
	// modulus
	//
	err = tpmProvider.CreateEk(ownerSecretKey, endorsementSecretKey, TPM_SIMULATOR_EK)
	if err != nil {
		return err
	}

	ekModulus, err := tpmProvider.ReadPublic(TPM_SIMULATOR_EK)
	if err != nil {
		return err
	}

	//
	// Use the modulus to create an RSA public key...
	//
	n := new(big.Int)
	n.SetBytes(ekModulus)

	ekPublicKey := rsa.PublicKey{N: n, E: int(0)} // assume zero exponent which is used in the default EK template

	pkixName := pkix.Name{
		Organization:  []string{"Intel"},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"2200 Mission College Blvd."},
		PostalCode:    []string{"95054"},
	}

	//
	// Generate a self signed root CA
	//
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 used in default EK template
	if err != nil {
		return err
	}

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               pkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//
	// Create an EK Certificate and sign it with the root CA
	//
	ekCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject:      pkixName,
		//		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().AddDate(-1, 0, 0),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		//		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	ekCertificateBytes, err := x509.CreateCertificate(rand.Reader, &ekCertTemplate, &rootCaTemplate, &ekPublicKey, caPrivateKey)
	if err != nil {
		return err
	}

	// Note:  Trying to parse the EK cert via go won't work because go's rsa package doesn't like
	// an rsa exponent value of '0', which is the default value specified in 'B.3.3 Template L-1: RSA 2048
	//  (Storage)' in the 'TCG EK Credential Profile'.
	//
	// _, err = x509.ParseCertificate(ekCertificateBytes)
	// if err != nil {
	// 	return fmt.Errorf("TPM Simulator: Failed to parse the EK Certificate: %w", err)
	// }

	//
	// Save the EK Certificate to the default nv index
	//
	err = tpmProvider.NvDefine(ownerSecretKey, ownerSecretKey, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE, uint16(len(ekCertificateBytes)))
	if err != nil {
		return err
	}

	err = tpmProvider.NvWrite(ownerSecretKey, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE, ekCertificateBytes)
	if err != nil {
		return err
	}

	return nil
}
