/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package log

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var defaultFmt = "$lv$[$pid$] $t$ $pkg$: $msg$; $flds$"
var defaultDelim = '$'
var defaultTimeFmt = time.RFC3339Nano // Milliseconds not available hence update to Nano

type LogFormatter struct {
	FormatDelimiter rune
	LineFormat      string
	TimeFormat      string
	LevelLength     int
	MaxLength       int

	setup sync.Once
}

func (f *LogFormatter) setupArgs() {
	if f.LineFormat == "" {
		f.LineFormat = defaultFmt
	}
	if f.TimeFormat == "" {
		f.TimeFormat = defaultTimeFmt
	}
	if f.FormatDelimiter == 0 ||
		f.FormatDelimiter == '\n' {
		f.FormatDelimiter = defaultDelim
	}
	if f.LevelLength > 7 {
		f.LevelLength = 7
	}
	if f.LevelLength < 4 {
		f.LevelLength = 4
	}
	if f.MaxLength < 1 {
		f.MaxLength = 99999
	}
	if f.MaxLength < 300 {
		f.MaxLength = 300
	}
}

func (f *LogFormatter) Format(e *log.Entry) ([]byte, error) {
	f.setup.Do(f.setupArgs)
	ret := ""
	tokens := strings.Split(f.LineFormat+"\n", string(f.FormatDelimiter))
	if len(tokens) != 13 {
		f.LineFormat = defaultFmt
		return nil, errors.New("Invalid format string")
	}
	for i := 0; i < 12; i += 2 {
		ret += tokens[i]
		switch tokens[i+1] {
		case "lv":
			lv := fmt.Sprintf("%-7v", e.Level.String())[:f.LevelLength]
			ret += strings.ToUpper(lv)
		case "t":
			ret += e.Time.Format(f.TimeFormat)
		case "pkg":
			if pkg, ok := e.Data["package"].(string); ok {
				ret += pkg
			}
		case "msg":
			ret += e.Message
		case "pid":
			if pid, ok := e.Data["pid"].(int); ok {
				ret += fmt.Sprintf("%05d", pid)
			}
		case "flds":
			fields := ""
			for k, v := range e.Data {
				switch k {
				case "package":
					continue
				case "pid":
					continue
				default:
					fields = fields + fmt.Sprintf(" %s=%v", k, v)
				}
			}
			if fields != "" {
				fields = fields[1:]
			}
			ret += fields
		}
		if len(ret) > f.MaxLength {
			break
		}
	}
	ret += tokens[12]
	if len(ret) > f.MaxLength {
		ret = ret[0:f.MaxLength] + "\n"
	}
	return []byte(ret), nil
}
