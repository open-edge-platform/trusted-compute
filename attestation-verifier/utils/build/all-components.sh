#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


echo "Installing Foundational Security pre-reqs..."
cd foundational-security/
chmod +x fs-prereq.sh;./fs-prereq.sh -s
cd ..

echo "Installing Workload Security pre-reqs"
cd workload-security/
chmod +x ws-prereq.sh

#Container-Conf-Docker
./ws-prereq.sh -d

#Container-Conf-CRIO
./ws-prereq.sh -c
