/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

type Cmd struct {
	Name        string
	DispStr     string
	Description string

	SubCmd     []Cmd
	SubCmdDesc string
	Flags      []CmdFlag

	AppFuncName string
}

type CmdFlag struct {
	Name        string
	Description string
	Required    bool

	DefInEnv bool
	Env      string
}
