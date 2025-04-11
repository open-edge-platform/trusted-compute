/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
	"text/tabwriter"
)

type PrintSettings struct {
	HelpStr          string
	UnknownCmdErrStr string

	DefaultIndent   int
	DefaultTabWidth int
	EnvAppendStrFmt string
}

var defaultPS = PrintSettings{
	HelpStr:          "Usage",
	UnknownCmdErrStr: "Invalid usage of command: ",

	DefaultIndent:   4,
	DefaultTabWidth: 8,
	EnvAppendStrFmt: " (env: %s)",
}

// PrintUsage prints sub commands and flags of this command
func (cmd *Cmd) PrintUsage(w io.Writer, ps *PrintSettings) {

	if ps == nil {
		ps = &defaultPS
	}
	fmt.Fprintln(w, ps.HelpStr)
	fmt.Fprintln(w, indentString(ps.DefaultIndent)+cmd.DispStr)

	if cmd.Flags != nil {
		cmd.printFlags(w, indentString(ps.DefaultIndent*2), ps)
	} else if cmd.SubCmd != nil {
		fmt.Fprintln(w, "")
		cmd.printSubCmds(w, ps)
	}
}

// PrintHelp prints sub commands and flags of this command,
// then print details of all subcommands with BFS
func (cmd *Cmd) PrintHelp(w io.Writer, ps *PrintSettings) {

	if ps == nil {
		ps = &defaultPS
	}
	fmt.Fprintln(w, ps.HelpStr)
	fmt.Fprintln(w, indentString(ps.DefaultIndent)+cmd.DispStr)

	var curCmd Cmd
	if cmd.SubCmd != nil {
		bfsQueue := append(make([]Cmd, 0), *cmd)
		for len(bfsQueue) > 0 {
			curCmd, bfsQueue = bfsQueue[0], bfsQueue[1:]
			if curCmd.SubCmd != nil {
				fmt.Fprintln(w, "")
				curCmd.printSubCmds(w, ps)
				bfsQueue = append(bfsQueue, curCmd.SubCmd...)
			}
		}
	}
}

// PrintMisuse prints an error message regarding the invalid use of command
// then calls cmd.PrintUsage() with the same io.Writer
func (cmd *Cmd) PrintMisuse(w io.Writer, err error, ps *PrintSettings) {
	if ps == nil {
		ps = &defaultPS
	}
	fmt.Fprintln(w, ps.UnknownCmdErrStr+err.Error())
	cmd.PrintUsage(w, ps)
}

// ----------------------------------------------------
// Unexported functions
// ----------------------------------------------------
func indentString(leadingSpaces int) string {
	return strings.Repeat(" ", leadingSpaces)
}

func (cmd *Cmd) printSubCmds(w io.Writer, ps *PrintSettings) {

	if cmd.SubCmd != nil {
		fmt.Fprintln(w, cmd.SubCmdDesc)

		tabW := new(tabwriter.Writer)
		defer func() {
			derr := tabW.Flush()
			if derr != nil {
				log.WithError(derr).Error("Error flushing tab")
			}
		}()
		tabW.Init(w, ps.DefaultTabWidth, ps.DefaultTabWidth, 2, '\t', 0)

		indent := indentString(ps.DefaultIndent)
		twoIndent := indentString(ps.DefaultIndent * 2)
		for i := 0; i < len(cmd.SubCmd); i++ {
			curCmd := cmd.SubCmd[i]
			if curCmd.DispStr != "" {
				fmt.Fprintln(tabW, indent+curCmd.DispStr+"\t"+curCmd.Description)
				if curCmd.Flags != nil {
					err := tabW.Flush()
					if err != nil {
						log.WithError(err).Errorf("could not flush tab")
					}
					curCmd.printFlags(w, twoIndent, ps)
				}
			}
		}
	}
}

func (cmd *Cmd) printFlags(w io.Writer, indent string, ps *PrintSettings) {

	if cmd.Flags != nil {
		tabW := new(tabwriter.Writer)
		defer func() {
			derr := tabW.Flush()
			if derr != nil {
				log.WithError(derr).Error("Error flushing tab")
			}
		}()
		tabW.Init(w, ps.DefaultTabWidth, ps.DefaultTabWidth, 2, '\t', 0)

		for i := 0; i < len(cmd.Flags); i++ {
			curFlag := cmd.Flags[i]
			curFlagDesc := curFlag.Description
			if curFlagDesc != "" {
				if curFlag.DefInEnv {
					curFlagDesc += fmt.Sprintf(ps.EnvAppendStrFmt, curFlag.Env)
				}
				fmt.Fprintln(tabW, indent+curFlag.Name+"\t"+curFlagDesc)
			}
		}
	}
}
