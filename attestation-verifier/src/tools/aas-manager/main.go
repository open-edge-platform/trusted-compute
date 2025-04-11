/*
Copyright © 2020 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/
package main

import (
	"os"
)

func main() {
	app := &App{}

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
