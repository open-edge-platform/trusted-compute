/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"errors"
	"io"
	"os"
	"strings"
)

type CmdArgs map[string]string

type ParsedCmd struct {
	Cmd  string
	Args CmdArgs
}

var (
	ErrCmdParse      = errors.New("Failed to parse command line input")
	ErrCmdArgMissing = errors.New("Invalid command line arguments, something missing")
	ErrCmdArgUndef   = errors.New("Invalid command line arguments, something undefined")
	ErrEnvArg        = errors.New("Failed to retrieve all argument from env")
)

// ValidateCmd checks if the command line arguments are valid
// and print help or error message to given io writers if PrintSettings is not nil;
// this function should be called on the root of Cmd tree of an application;
// return last successfully validated command, its index and an error if there is any
func (app *Cmd) ValidateCmd(args []string, stdW, errW io.Writer, ps *PrintSettings) (*Cmd, int, error) {

	if len(args) < 2 {
		if app.SubCmd == nil && app.Flags == nil {
			return app, 0, nil
		}
		if ps != nil {
			app.PrintHelp(errW, ps)
		}
		return nil, -1, ErrCmdParse
	}
	curNode := *app
	argIdx := 1
	subCmdIdx := 0
	for subCmdIdx < len(curNode.SubCmd) &&
		argIdx < len(args) {
		if args[argIdx] == "-h" ||
			args[argIdx] == "help" ||
			args[argIdx] == "--help" {
			if ps != nil {
				curNode.PrintHelp(stdW, ps)
			}
			return nil, argIdx, nil
		}
		if curNode.SubCmd[subCmdIdx].Name == args[argIdx] {
			curNode = curNode.SubCmd[subCmdIdx]
			subCmdIdx = 0
			argIdx++
		} else {
			subCmdIdx++
		}
	}
	if curNode.SubCmd != nil {
		if ps != nil {
			curNode.PrintMisuse(errW, ErrCmdParse, ps)
		}
		return &curNode, argIdx, ErrCmdParse
	}
	return &curNode, argIdx, nil
}

// GetCliArgs parses command line flags for the Cmd from which its called
// and return the result in ParsedCmd struct
func (cmd *Cmd) GetCliArgs(args []string, startIdx int) (*ParsedCmd, error) {

	argsMap := make(CmdArgs)
	var retErr error

	if startIdx < 1 {
		return nil, ErrCmdParse
	}
	for i := 0; i < len(cmd.Flags); i++ {
		curFlag := cmd.Flags[i]
		if curFlag.Required {
			argsMap[curFlag.Name] = ""
		}
	}
	var lastOpt string
	for i := startIdx; i < len(args); i++ {
		curStr := args[i]
		if lastOpt != "" {
			argsMap[lastOpt] = curStr
			lastOpt = ""
		}
		if strings.HasPrefix(curStr, "--") {
			equalSign := strings.Index(curStr, "=")
			if equalSign > -1 {
				opt := curStr[2:equalSign]
				argsMap[opt] = curStr[equalSign+1:]
			} else {
				lastOpt = curStr[2:]
			}
		}
	}
	for _, v := range argsMap {
		if v == "" {
			retErr = ErrCmdArgMissing
		}
	}
	return &ParsedCmd{Cmd: cmd.Name, Args: argsMap}, retErr
}

// GetEnvArgs retrieves missing flags from environment for the Cmd
// from which its called and append it to the given ParsedCmd struct
func (cmd *Cmd) GetEnvArgs(parsed *ParsedCmd) error {

	argsMap := parsed.Args
	var retErr error

	for i := 0; i < len(cmd.Flags); i++ {
		curFlag := cmd.Flags[i]
		if curFlag.DefInEnv &&
			argsMap[curFlag.Name] == "" {
			envStr := os.Getenv(curFlag.Env)
			if envStr == "" {
				retErr = ErrEnvArg
			}
			argsMap[curFlag.Name] = envStr
		}
	}
	return retErr
}
