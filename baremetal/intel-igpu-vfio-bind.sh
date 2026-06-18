#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

CDI_FILE=/etc/cdi/intel-igpu-tc-cdi.yaml
DRI_SNAPSHOT=()
GPU_PCI_FULL=""
GPU_VENDOR=""
GPU_DEVICE=""

if [ "$EUID" -ne 0 ]; then echo "Must be run as root"; exit 1; fi

detect_gpu() {
    local line ids
    line=$(lspci -Dnn | grep -E 'VGA compatible controller.*Intel' | head -1)
    if [ -z "$line" ]; then echo "ERROR: No Intel iGPU found!"; exit 1; fi
    GPU_PCI_FULL=$(echo "$line" | awk '{print $1}')
    ids=$(echo "$line" | grep -o '\[[0-9a-fA-F]*:[0-9a-fA-F]*\]' | tail -1 | tr -d '[]')
    GPU_VENDOR=${ids%:*}
    GPU_DEVICE=${ids#*:}
    echo "GPU: $GPU_PCI_FULL ($GPU_VENDOR:$GPU_DEVICE)"
}

current_driver() {
    local link="/sys/bus/pci/devices/$GPU_PCI_FULL/driver"
    if [ -L "$link" ]; then basename "$(readlink "$link")"; else echo "unbound"; fi
}

iommu_group_for_gpu() {
    local link="/sys/bus/pci/devices/$GPU_PCI_FULL/iommu_group"
    if [ -L "$link" ]; then
        basename "$(readlink -f "$link")"
    else
        echo "ERROR: No IOMMU group found for $GPU_PCI_FULL"
        exit 1
    fi
}

platform_native_driver() {
    local modalias driver
    modalias=$(cat "/sys/bus/pci/devices/$GPU_PCI_FULL/modalias" 2>/dev/null) || { echo "i915"; return; }
    driver=$(modprobe --dry-run --resolve-alias "$modalias" 2>/dev/null | head -1)
    echo "${driver:-i915}"
}

snapshot_dri_nodes() {
    local dev hmaj hmin maj min
    DRI_SNAPSHOT=()
    for dev in /dev/dri/card* /dev/dri/renderD*; do
        [ -e "$dev" ] || continue
        read -r hmaj hmin < <(stat -c "%t %T" "$dev")
        maj=$((16#$hmaj))
        min=$((16#$hmin))
        DRI_SNAPSHOT+=("$dev:$maj:$min")
    done
}

append_cdi_device_node() {
    local path="$1" major="$2" minor="$3"
    printf '%s\n' \
        "        - path: $path" \
        '          type: c' \
        "          major: $major" \
        "          minor: $minor" \
        '          fileMode: 432' \
        '          permissions: rw' >> "$CDI_FILE"
}

write_cdi_spec() {
    local vfio_group vfio_group_dev hmaj hmin maj min entry path node_major node_minor

    vfio_group=$(iommu_group_for_gpu)
    vfio_group_dev="/dev/vfio/$vfio_group"
    if [ ! -e /dev/vfio/vfio ] || [ ! -e "$vfio_group_dev" ]; then
        echo "ERROR: Missing VFIO nodes for CDI generation"
        exit 1
    fi
    mkdir -p "$(dirname "$CDI_FILE")"
    printf '%s\n' \
        'cdiVersion: "0.7.0"' \
        'kind: gpu.intel.com/igpu' \
        'devices:' \
        '  - name: tc' \
        '    containerEdits:' \
        '      deviceNodes:' > "$CDI_FILE"
    read -r hmaj hmin < <(stat -c "%t %T" /dev/vfio/vfio)
    maj=$((16#$hmaj))
    min=$((16#$hmin))
    append_cdi_device_node "/dev/vfio/vfio" "$maj" "$min"
    read -r hmaj hmin < <(stat -c "%t %T" "$vfio_group_dev")
    maj=$((16#$hmaj))
    min=$((16#$hmin))
    append_cdi_device_node "$vfio_group_dev" "$maj" "$min"
    for entry in "${DRI_SNAPSHOT[@]}"; do
        IFS=: read -r path node_major node_minor <<< "$entry"
        append_cdi_device_node "$path" "$node_major" "$node_minor"
    done
    echo "CDI spec written to $CDI_FILE"
}

stop_display_manager() {
    local svc
    for svc in display-manager gdm; do
        systemctl stop "$svc" 2>/dev/null || true
    done
    pkill -9 -f "Xwayland|gnome-session|gnome-shell|mutter" 2>/dev/null || true
}

start_display_manager() {
    local svc retries=10
    for svc in display-manager gdm; do
        if systemctl start "$svc" 2>/dev/null; then
            while [ $retries -gt 0 ]; do
                systemctl is-active --quiet "$svc" && return 0
                retries=$((retries - 1))
                read -rt 1 || true
            done
            return 0
        fi
    done
    return 0
}

bind_to_vfio() {
    local drv
    echo "Binding GPU to vfio-pci..."
    snapshot_dri_nodes
    stop_display_manager
    modprobe vfio-pci 2>/dev/null || true
    drv=$(current_driver)
    echo "vfio-pci" > "/sys/bus/pci/devices/$GPU_PCI_FULL/driver_override" 2>/dev/null || true
    if [ "$drv" != "unbound" ] && [ "$drv" != "vfio-pci" ]; then
        if [ -e "/sys/bus/pci/drivers/$drv/$GPU_PCI_FULL" ]; then
            echo "$GPU_PCI_FULL" > "/sys/bus/pci/drivers/$drv/unbind" 2>/dev/null || true
        fi
    fi
    echo "$GPU_VENDOR $GPU_DEVICE" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null || true
    echo "$GPU_PCI_FULL" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
    if [ ! -e "/sys/bus/pci/drivers/vfio-pci/$GPU_PCI_FULL" ]; then
        echo "$GPU_PCI_FULL" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    fi
    if [ "$(current_driver)" != "vfio-pci" ]; then
        echo "FAILED: driver=$(current_driver)"
        exit 1
    fi
    echo "SUCCESS: GPU bound to vfio-pci"
    write_cdi_spec
}

unbind_from_vfio() {
    local preferred
    echo "Unbinding from vfio-pci..."
    preferred=$(platform_native_driver)
    printf '\000' > "/sys/bus/pci/devices/$GPU_PCI_FULL/driver_override" 2>/dev/null || true
    if [ -e "/sys/bus/pci/drivers/vfio-pci/$GPU_PCI_FULL" ]; then
        echo "$GPU_PCI_FULL" > /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null || true
    fi
    modprobe "$preferred" 2>/dev/null || true
    if [ -d "/sys/bus/pci/drivers/$preferred" ]; then
        echo "$GPU_PCI_FULL" > "/sys/bus/pci/drivers/$preferred/bind" 2>/dev/null || true
    fi
    if [ ! -e "/sys/bus/pci/drivers/$preferred/$GPU_PCI_FULL" ]; then
        echo "$GPU_PCI_FULL" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    fi
    if [ "$(current_driver)" = "$preferred" ]; then
        echo "SUCCESS: GPU restored to $(current_driver)"
        echo "Restarting display manager..."
        echo "1" > /sys/bus/pci/rescan 2>/dev/null || true
        start_display_manager
        return 0
    fi
    echo "FAILED: could not restore native driver (current: $(current_driver))"
    exit 1
}

case "${1:-bind}" in
    bind)
        detect_gpu
        if [ -e "/sys/bus/pci/drivers/vfio-pci/$GPU_PCI_FULL" ]; then
            echo "GPU already bound to vfio-pci"
            exit 0
        fi
        bind_to_vfio
        ;;
    unbind)
        detect_gpu
        if [ ! -e "/sys/bus/pci/drivers/vfio-pci/$GPU_PCI_FULL" ]; then
            echo "GPU already bound to $(current_driver)"
            exit 0
        fi
        unbind_from_vfio
        ;;
    *)
        echo "Usage: $0 {bind|unbind}"
        exit 1
        ;;
esac
