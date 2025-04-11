/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/nats-io/nkeys"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type CreateCredentials struct {
	CreateCredentials        bool
	NatsConfig               config.NatsConfig
	ConsoleWriter            io.Writer
	OperatorSeedFile         string
	AccountSeedFile          string
	AccountConfigurationFile string
}

const createCredentialsHelpPrompt = "Following environment variables are optional for create-credentials setup:"

var createCredentialsEnvHelp = map[string]string{
	"CREATE_CREDENTIALS":                "Trigger to run create-credentials setup task when set to True. Default is False",
	"NATS_OPERATOR_NAME":                "Set the NATS operator name, default is \"ISecL-operator\"",
	"NATS_OPERATOR_CREDENTIAL_VALIDITY": "Set the NATS operator credential validity in terms of duration (ex: \"300ms\",\"-1.5h\" or \"2h45m\"), default is 5 years",
	"NATS_ACCOUNT_NAME":                 "Set the NATS account name, default is \"ISecL-account\"",
	"NATS_ACCOUNT_CREDENTIAL_VALIDITY":  "Set the NATS account credential validity in terms of duration (ex: \"300ms\",\"-1.5h\" or \"2h45m\"), default is 5 years",
	"NATS_USER_CREDENTIAL_VALIDITY":     "Set the NATS user credential validity in terms of duration (ex: \"300ms\",\"-1.5h\" or \"2h45m\"), default is 1 year",
}

func (cc *CreateCredentials) Run() error {
	defaultLog.Trace("tasks/create_credentials:Run() Entering")
	defer defaultLog.Trace("tasks/create_credentials:Run() Leaving")

	if !cc.CreateCredentials {
		fmt.Println("Skipping \"create-credentials\" setup task. Please set CREATE_CREDENTIALS env value to true to run the task.....")
		return nil
	}

	operatorKeyPair, err := nkeys.CreateOperator()
	if err != nil {
		return errors.Wrap(err, "Error creating operator nkeys")
	}

	operatorSeed, err := operatorKeyPair.Seed()
	if err != nil {
		return errors.Wrap(err, "Error fetching operator seed")
	}

	operatorToken, err := common.CreateJWTToken(operatorKeyPair, operatorKeyPair, constants.Operator, "",
		cc.NatsConfig.Operator)
	if err != nil {
		return errors.Wrap(err, "Error creating operator JWT")
	}
	log.Debug("Operator token is : ", operatorToken)

	err = ioutil.WriteFile(cc.OperatorSeedFile, operatorSeed, 0600)
	if err != nil {
		return errors.Wrap(err, "Error writing operator seed and private key to file")
	}

	accountKeyPair, err := nkeys.CreateAccount()
	if err != nil {
		return errors.Wrap(err, "Error creating account nkeys")
	}

	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return errors.Wrap(err, "Error fetching public key of account")
	}
	log.Debug("Account Public Key : ", accountPublicKey)

	accountSeed, err := accountKeyPair.Seed()
	if err != nil {
		return errors.Wrap(err, "Error fetching seed of account")
	}

	accountToken, err := common.CreateJWTToken(accountKeyPair, operatorKeyPair, constants.Account, "",
		cc.NatsConfig.Account)
	if err != nil {
		return errors.Wrap(err, "Error creating account JWT")
	}
	log.Debug("Account token is : ", accountToken)

	err = ioutil.WriteFile(cc.AccountSeedFile, accountSeed, 0600)
	if err != nil {
		return errors.Wrap(err, "Error writing private key and seed of account to file")
	}

	//Create fixed format for server configuration
	formattedConf := fmt.Sprintf("// Operator %s\noperator: %s\n\nresolver: MEMORY\n\nresolver_preload: {\n"+
		" // Account %s\n %s: %s\n}", cc.NatsConfig.Operator.Name, operatorToken, cc.NatsConfig.Account.Name,
		accountPublicKey, accountToken)

	err = ioutil.WriteFile(cc.AccountConfigurationFile, []byte(formattedConf), 0600)
	if err != nil {
		return errors.Wrap(err, "Error writing server configuration to file")
	}

	fmt.Fprintln(cc.ConsoleWriter, "\nPlease copy the NATS server configuration printed on console:")
	fmt.Fprintln(cc.ConsoleWriter, "\n"+formattedConf+"\n")

	return nil
}

func (cc *CreateCredentials) Validate() error {
	defaultLog.Trace("tasks/create_credentials:Validate() Entering")
	defer defaultLog.Trace("tasks/create_credentials:Validate() Leaving")

	if !cc.CreateCredentials {
		return nil
	}
	_, err := os.Stat(cc.OperatorSeedFile)
	if err != nil {
		return err
	}
	_, err = os.Stat(cc.AccountSeedFile)
	if err != nil {
		return err
	}
	_, err = os.Stat(cc.AccountConfigurationFile)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CreateCredentials) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, createCredentialsHelpPrompt, "", createCredentialsEnvHelp)
	fmt.Fprintln(w, "")
}

func (cc *CreateCredentials) SetName(n, e string) {

}
