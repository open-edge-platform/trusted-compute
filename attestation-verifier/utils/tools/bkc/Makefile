# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := "v5.1.0"
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
BUILDDATE_FILENAME := $(shell TZ=UTC date +%Y-%m-%dT%H-%M-%S)

bkc-tool:
	cd cmd && \
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy && \
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go build -gcflags=all="-N -l" \
		-ldflags "-X main.Version=$(VERSION) -X main.Build=$(GITCOMMIT) -X main.BuildDate=$(BUILDDATE)" \
		-o bkc-tool.bin

installer: bkc-tool
	mkdir -p out/installer
	cp cmd/*.bin out/installer/
	cp build/installer/* out/installer/
	chmod +x out/installer/*.bin
	chmod +x out/installer/*.sh
	makeself out/installer out/bkc-tool-$(BUILDDATE_FILENAME).bin "BKC Tool $(VERSION)" ./installer.sh
	rm -rf out/installer

all: clean installer

clean:
	rm -rf out/

.PHONY: all clean installer
