# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

TEMPLATE_REL_VERSION_FLAVOR := v4.0.0
TEMPLATE_REL_VERSION_PAGINATION := v5.1.0

.PHONY: flavor-template hvs-pagination

all: flavor-template hvs-pagination

flavor-template:
	mkdir -p out
	cd src/flavor-template && go build -ldflags "-X main.BuildVersion=$(TEMPLATE_REL_VERSION_FLAVOR)" -o $(TEMPLATE_REL_VERSION_FLAVOR)_flavor_convert && mv $(TEMPLATE_REL_VERSION_FLAVOR)_flavor_convert ../../out
	$ echo "upgrades/hvs/db/out/$(TEMPLATE_REL_VERSION_FLAVOR)_flavor_convert successfully created"

hvs-pagination:
	mkdir -p out
	cd src/hvs-pagination && go build -ldflags "-X main.BuildVersion=$(TEMPLATE_REL_VERSION_PAGINATION)" -o $(TEMPLATE_REL_VERSION_PAGINATION)_hvs_pagination && mv $(TEMPLATE_REL_VERSION_PAGINATION)_hvs_pagination ../../out
	$ echo "upgrades/hvs/db/out/$(TEMPLATE_REL_VERSION_PAGINATION)_hvs_pagination successfully created"
