/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"os"
	"testing"
)

// Run with command: go test --count=1 -v
// to see the result from stdout and created files

var printSettings = PrintSettings{
	HelpStr:          "Usage",
	UnknownCmdErrStr: "Invalid usage of command: ",

	DefaultIndent:   4,
	DefaultTabWidth: 8,
	EnvAppendStrFmt: " (env: %s)",
}

var appCmd = Cmd{Name: "app", DispStr: "./app <cmd> args", SubCmdDesc: "Avaliable Commands:",
	SubCmd: []Cmd{help, run, setup, start, stop, status, uninstall, version}}

var help = Cmd{DispStr: "help|-h|--help", Description: "Show this help message"}

var run = Cmd{Name: "run"}

var (
	start     = Cmd{Name: "start", DispStr: "start", Description: "Start the app"}
	stop      = Cmd{Name: "stop", DispStr: "stop", Description: "Stop the app"}
	status    = Cmd{Name: "status", DispStr: "status", Description: "Show status of the app"}
	uninstall = Cmd{Name: "uninstall", DispStr: "uninstall", Description: "Uninstall app"}
	version   = Cmd{Name: "version", DispStr: "version", Description: "Show version of the app"}

	setup = Cmd{Name: "setup",
		DispStr:     "setup <task>",
		Description: "Run setup task",
		SubCmdDesc:  "Avaliable Tasks for setup:",
		SubCmd:      []Cmd{task1, task2, task3, all}}
)

var (
	task1Fg1 = CmdFlag{Name: "arg1",
		Description: "arg1 description",
		Required:    true,
		DefInEnv:    true, Env: "APP_ARG1_ENV"}
	task1Fg2 = CmdFlag{Name: "arg2",
		Description: "arg2 description",
		Required:    false,
		DefInEnv:    true, Env: "APP_ARG2_ENV"}
	task1Fg3 = CmdFlag{Name: "arg3",
		Description: "arg3 description",
		Required:    true,
		DefInEnv:    true, Env: "APP_ARG3_ENV"}

	task1 = Cmd{Name: "task1",
		DispStr:     "setup task1 [--args=val]",
		Description: "Description 1",
		Flags:       []CmdFlag{task1Fg1, task1Fg2, task1Fg3}}
)

var (
	task2Fg1 = CmdFlag{Name: "arg21",
		Description: "arg1 description",
		Required:    true,
		DefInEnv:    false, Env: ""}

	task2Fg2 = CmdFlag{Name: "arg22",
		Description: "arg2 description",
		Required:    false,
		DefInEnv:    false, Env: ""}

	task2 = Cmd{Name: "task2",
		DispStr:     "setup task2 <--arg21=val> <--arg22=val>",
		Description: "Description 2",
		Flags:       []CmdFlag{task2Fg1, task2Fg2}}
)

var (
	task3 = Cmd{Name: "task3", DispStr: "setup task3", Description: "Description 3"}

	all = Cmd{Name: "all", DispStr: "setup all",
		Description: "Run all setups, arguments should be defined in env"}
)

func TestPrint(t *testing.T) {

	// appCmd.PrintHelp(os.Stdout, &printSettings)
	// appCmd.PrintUsage(os.Stdout, &printSettings)

	setup.PrintUsage(os.Stdout, &printSettings)
	all.PrintUsage(os.Stdout, &printSettings)
	task1.PrintUsage(os.Stdout, &printSettings)
	task2.PrintUsage(os.Stdout, &printSettings)
	task3.PrintUsage(os.Stdout, &printSettings)

	// err := errors.New("test error")
	// setup.PrintMisuse(os.Stdout, err, &printSettings)
	// all.PrintMisuse(os.Stdout, err, &printSettings)
	// task1.PrintMisuse(os.Stdout, err, &printSettings)
	// task2.PrintMisuse(os.Stdout, err, &printSettings)
	// task3.PrintMisuse(os.Stdout, err, &printSettings)
}

func TestValidate(t *testing.T) {

	var args []string
	var c *Cmd
	var i int
	var err error

	// good
	args = []string{"app", "setup", "task1", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "all", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "task3", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "run", "task1", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "help", "abc", ""}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "start", "task1", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	// bad
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "bad-input", "task1", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "bad-input", "--flag"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	fmt.Println(c, i)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func TestCliArgs(t *testing.T) {

	var args []string
	var c *Cmd
	var p_c *ParsedCmd
	var i int
	var err error

	// good
	args = []string{"app", "setup", "task1", "--arg1=123", "--arg=234", "--arg3=345"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	p_c, err = c.GetCliArgs(args, i)
	fmt.Println(p_c)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "task1", "--arg1", "123", "--arg3=345", "--arg2", "123", "--arg20", "123"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	p_c, err = c.GetCliArgs(args, i)
	fmt.Println(p_c)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "task2", "--arg21", "123"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	p_c, err = c.GetCliArgs(args, i)
	fmt.Println(p_c)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")

	// bad
	args = []string{"app", "setup", "task1", "--arg2", "123"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	p_c, err = c.GetCliArgs(args, i)
	fmt.Println(p_c)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("-----------------------------------------------------------------")
	args = []string{"app", "setup", "task2", "--arg2", "123"}
	c, i, err = appCmd.ValidateCmd(args, os.Stdout, os.Stderr, &printSettings)
	p_c, err = c.GetCliArgs(args, i)
	fmt.Println(p_c)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func TestEnv(t *testing.T) {

}
