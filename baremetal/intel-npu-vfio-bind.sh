#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

CDI_FILE=/etc/cdi/intel-npu-tc-cdi.yaml
ACCEL_SNAPSHOT=()
NPU_PCI_FULL=""
NPU_VENDOR=""
NPU_DEVICE=""

if [ "$EUID" -ne 0 ]; then echo "Must be run as root"; exit 1; fi

if ! command -v lspci > /dev/null 2>&1; then
    echo "ERROR: 'lspci' not found. Install pciutils (e.g., 'apt install pciutils' or 'dnf install pciutils')." >&2
    exit 1
fi

detect_npu() {
    local line ids
    if [ -e /sys/class/accel/accel0 ] && [ -L /sys/class/accel/accel0/device/driver ] && [ "$(basename "$(readlink -f /sys/class/accel/accel0/device/driver)")" = "intel_vpu" ]; then
        NPU_PCI_FULL=$(basename "$(readlink -f /sys/class/accel/accel0/device)")
        line=$(lspci -Dnn -s "$NPU_PCI_FULL" | head -1 || true)
    else
        line=$(lspci -Dnn | grep -iE 'Processing accelerators.*Intel.*NPU|Meteor Lake NPU' | head -1 || true)
        if [ -z "$line" ]; then echo "ERROR: No Intel NPU found!"; exit 1; fi
        NPU_PCI_FULL=$(echo "$line" | awk '{print $1}')
    fi
    if [ -z "$line" ]; then
        NPU_VENDOR=$(cat "/sys/bus/pci/devices/$NPU_PCI_FULL/vendor" | sed 's/^0x//')
        NPU_DEVICE=$(cat "/sys/bus/pci/devices/$NPU_PCI_FULL/device" | sed 's/^0x//')
    else
        ids=$(echo "$line" | grep -o '\[[0-9a-fA-F]*:[0-9a-fA-F]*\]' | tail -1 | tr -d '[]')
        NPU_VENDOR=${ids%:*}
        NPU_DEVICE=${ids#*:}
    fi
    echo "NPU: $NPU_PCI_FULL ($NPU_VENDOR:$NPU_DEVICE)"
}

current_driver() {
    local link="/sys/bus/pci/devices/$NPU_PCI_FULL/driver"
    if [ -L "$link" ]; then basename "$(readlink "$link")"; else echo "unbound"; fi
}

iommu_group_for_npu() {
    local link="/sys/bus/pci/devices/$NPU_PCI_FULL/iommu_group"
    if [ -L "$link" ]; then
        basename "$(readlink -f "$link")"
    else
        echo "ERROR: No IOMMU group found for $NPU_PCI_FULL"
        exit 1
    fi
}

print_vfio_device() {
    local vfio_group
    vfio_group=$(iommu_group_for_npu)
    echo "VFIO device: /dev/vfio/$vfio_group"
}

platform_native_driver() {
    local modalias driver
    modalias=$(cat "/sys/bus/pci/devices/$NPU_PCI_FULL/modalias" 2>/dev/null) || { echo "intel_vpu"; return; }
    driver=$(modprobe -R "$modalias" 2>/dev/null | head -1 | xargs basename | sed 's/\.ko$//')
    echo "${driver:-intel_vpu}"
}

snapshot_accel_nodes() {
    local sysnode name pci hmaj hmin maj min dev
    ACCEL_SNAPSHOT=()

    for sysnode in /sys/class/accel/accel*; do
        [ -e "$sysnode" ] || continue
        name=$(basename "$sysnode")
        pci=$(basename "$(readlink -f "$sysnode/device")")
        [ "$pci" = "$NPU_PCI_FULL" ] || continue

        dev="/dev/accel/$name"
        [ -e "$dev" ] || continue
        read -r hmaj hmin < <(stat -c "%t %T" "$dev")
        maj=$((16#$hmaj))
        min=$((16#$hmin))
        ACCEL_SNAPSHOT+=("$dev:$maj:$min")
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

    vfio_group=$(iommu_group_for_npu)
    vfio_group_dev="/dev/vfio/$vfio_group"
    if [ ! -e /dev/vfio/vfio ] || [ ! -e "$vfio_group_dev" ]; then
        echo "ERROR: Missing VFIO nodes for CDI generation"
        exit 1
    fi
    mkdir -p "$(dirname "$CDI_FILE")"
    printf '%s\n' \
        'cdiVersion: "0.7.0"' \
        'kind: npu.intel.com/npu' \
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
    for entry in "${ACCEL_SNAPSHOT[@]}"; do
        IFS=: read -r path node_major node_minor <<< "$entry"
        append_cdi_device_node "$path" "$node_major" "$node_minor"
    done
    echo "CDI spec written to $CDI_FILE"
}

bind_to_vfio() {
    local drv
    echo "Binding NPU to vfio-pci..."
    snapshot_accel_nodes
    modprobe vfio-pci 2>/dev/null || true
    drv=$(current_driver)
    echo "vfio-pci" > "/sys/bus/pci/devices/$NPU_PCI_FULL/driver_override" 2>/dev/null || true
    if [ "$drv" != "unbound" ] && [ "$drv" != "vfio-pci" ]; then
        if [ -e "/sys/bus/pci/drivers/$drv/$NPU_PCI_FULL" ]; then
            echo "$NPU_PCI_FULL" > "/sys/bus/pci/drivers/$drv/unbind" 2>/dev/null || true
        fi
    fi
    echo "$NPU_VENDOR $NPU_DEVICE" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null || true
    echo "$NPU_PCI_FULL" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
    if [ ! -e "/sys/bus/pci/drivers/vfio-pci/$NPU_PCI_FULL" ]; then
        echo "$NPU_PCI_FULL" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    fi
    if [ "$(current_driver)" != "vfio-pci" ]; then
        echo "FAILED: driver=$(current_driver)"
        exit 1
    fi
    echo "SUCCESS: NPU bound to vfio-pci"
    print_vfio_device
    write_cdi_spec
}

unbind_from_vfio() {
    local preferred
    echo "Unbinding from vfio-pci..."
    preferred=$(platform_native_driver)
    echo '' > "/sys/bus/pci/devices/$NPU_PCI_FULL/driver_override" 2>/dev/null || true
    if [ -e "/sys/bus/pci/drivers/vfio-pci/$NPU_PCI_FULL" ]; then
        echo "$NPU_PCI_FULL" > /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null || true
        echo "$NPU_VENDOR $NPU_DEVICE" > /sys/bus/pci/drivers/vfio-pci/remove_id 2>/dev/null || true
    fi
    modprobe "$preferred" 2>/dev/null || true
    if [ -d "/sys/bus/pci/drivers/$preferred" ]; then
        echo "$NPU_PCI_FULL" > "/sys/bus/pci/drivers/$preferred/bind" 2>/dev/null || true
    fi
    if [ ! -e "/sys/bus/pci/drivers/$preferred/$NPU_PCI_FULL" ]; then
        echo "$NPU_PCI_FULL" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    fi
    if [ "$(current_driver)" = "$preferred" ]; then
        echo "SUCCESS: NPU restored to $(current_driver)"
        echo "1" > /sys/bus/pci/rescan 2>/dev/null || true
        return 0
    fi
    echo "FAILED: could not restore native driver (current: $(current_driver))"
    exit 1
}

case "${1:-}" in
    bind)
        detect_npu
        if [ -e "/sys/bus/pci/drivers/vfio-pci/$NPU_PCI_FULL" ]; then
            echo "NPU already bound to vfio-pci"
            print_vfio_device
            exit 0
        fi
        bind_to_vfio
        ;;
    unbind)
        detect_npu
        if [ ! -e "/sys/bus/pci/drivers/vfio-pci/$NPU_PCI_FULL" ]; then
            echo "NPU already bound to $(current_driver)"
            exit 0
        fi
        unbind_from_vfio
        ;;
    status)
        detect_npu
        echo "NPU: $NPU_PCI_FULL | driver: $(current_driver)"
        print_vfio_device
        ;;
    "")
        echo "Usage: $0 {bind|unbind|status}"
        exit 1
        ;;
    *)
        echo "Usage: $0 {bind|unbind|status}"
        exit 1
        ;;
esac
