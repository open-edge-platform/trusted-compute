/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"io"

	"github.com/pkg/errors"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

type Admin struct {
	config.AASConfig
	ServiceConfigPtr *config.AASConfig
	DatabaseFactory  func() (domain.AASDatabase, error)
	ConsoleWriter    io.Writer
	envPrefix        string
	commandName      string
}

const adminEnvHelpPrompt = "Following environment variables are required for admin setup:"

var adminEnvHelp = map[string]string{
	"AAS_ADMIN_USERNAME": "Authentication and Authorization Service Admin Username",
	"AAS_ADMIN_PASSWORD": "Authentication and Authorization Service Admin Password",
}

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a Admin) Run() error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")

	db, err := a.DatabaseFactory()
	if err != nil {
		return errors.Wrap(err, "setup admin: failed to open database")
	}
	defer db.Close()

	var adminRoles types.Roles

	for _, roleCreate := range consts.GetDefaultAdministratorRoles() {
		role, err := createRole(db, roleCreate)
		if err != nil {
			return errors.Wrapf(err, "setup admin: could not create role in database - error %v", err)
		}
		adminRoles = append(adminRoles, *role)
	}

	a.ServiceConfigPtr.Username = a.Username
	a.ServiceConfigPtr.Password = a.Password

	err = addDBUser(db, a.ServiceConfigPtr.Username, a.ServiceConfigPtr.Password, adminRoles)
	if err != nil {
		return errors.Wrap(err, "setup admin: failed to add user and roles to database")
	}
	secLog.Infof("%s: Finished setup for admin %s:", commLogMsg.UserAdded, a.ServiceConfigPtr.Username)
	secLog.Infof("%s: Finished setup for admin %s:", commLogMsg.PrivilegeModified, a.ServiceConfigPtr.Username)

	return nil
}

func (a Admin) Validate() error {
	if a.ServiceConfigPtr.Username == "" {
		return errors.New("Service username is not set")
	}
	if a.ServiceConfigPtr.Password == "" {
		return errors.New("Service password is not set")
	}
	return nil
}

func (a Admin) SetName(n, e string) {
	a.commandName = n
	a.envPrefix = setup.PrefixUnderscroll(e)
}

func (a Admin) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, adminEnvHelpPrompt, a.envPrefix, adminEnvHelp)
	fmt.Fprintln(w, "")
}
