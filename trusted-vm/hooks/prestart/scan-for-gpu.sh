#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# OCI prestart hook: Wait for GPU render node before container process starts.
# Only activates when a PCI display device (class 0x0300xx) is present in the guest.
# Handles i915 (Raptor Lake), xe (Panther Lake+), and any render node number.

# Check if any PCI device with display class (0x0300xx) exists
if ! ls /sys/bus/pci/devices/*/class 2>/dev/null | \
     xargs grep -ql "0x0300" 2>/dev/null; then
    exit 0  # No GPU device, skip wait
fi

# Wait for any render node to appear (up to 5 seconds)
# Note: periodic stderr output keeps kata-agent poll alive (prevents 1s idle timeout)
for i in $(seq 1 50); do
    if ls /dev/dri/renderD* 1>/dev/null 2>&1; then
        echo "GPU ready" >&2
        exit 0
    fi
    echo "waiting for GPU render node ($i)..." >&2
    sleep 0.1
done

# Timeout - continue anyway (agent logs the hook output as warning)
echo "GPU render node not found after 5s, continuing" >&2
exit 0
