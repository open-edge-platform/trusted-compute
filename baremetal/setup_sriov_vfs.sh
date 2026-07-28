#!/bin/bash

# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# M = total VFs to create; N = VFs to bind to vfio-pci (N <= M)
# Defaults: create all hardware-supported VFs, bind all of them
TOTAL_VFS="${TOTAL_VFS:-}"   # M — empty means use sriov_totalvfs
BIND_VFS="${BIND_VFS:-}"     # N — empty means same as TOTAL_VFS
CDI_DIR="${CDI_DIR:-/etc/cdi}"

GTT_SPARE_PF=$((500 * 1024 * 1024))
CONTEXT_SPARE_PF=9216
DOORBELL_SPARE_PF=32
VFSCHED_EXECQ=25
VFSCHED_TIMEOUT=500000

PF_ADDR="0000:00:02.0"
VENDOR=""
DEVICE=""

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ── GPU readiness check ───────────────────────────────────────────────────────
check_gpu_ready() {
    if [ ! -d "/sys/bus/pci/devices/$PF_ADDR" ]; then
        echo "PCI device $PF_ADDR not found"; return 1
    fi

    local drm_driver
    drm_driver=$(lspci -D -k -s "${PF_ADDR#*:}" 2>/dev/null \
        | grep "Kernel driver in use" | awk -F ':' '{print $2}' | xargs)
    if [ -z "$drm_driver" ]; then
        echo "No kernel driver loaded yet"; return 1
    fi
    if [[ "$drm_driver" != "i915" && "$drm_driver" != "xe" ]]; then
        echo "Unexpected driver: $drm_driver (expected i915 or xe)"; return 1
    fi

    if [ ! -d "/sys/class/drm/card0" ]; then
        echo "DRM card0 not found"; return 1
    fi
    if [ ! -f "/sys/class/drm/card0/device/sriov_totalvfs" ]; then
        echo "SR-IOV totalvfs file not found"; return 1
    fi

    local total_vfs
    total_vfs=$(cat /sys/class/drm/card0/device/sriov_totalvfs 2>/dev/null)
    if [ -z "$total_vfs" ]; then
        echo "Cannot read sriov_totalvfs"; return 1
    fi

    if [[ "$drm_driver" == "xe" && ! -d "/sys/kernel/debug/dri/0" ]]; then
        echo "XE driver debugfs not ready"; return 1
    fi

    log "GPU ready (driver: $drm_driver, sriov_totalvfs: $total_vfs)"
    return 0
}

# ── VF BDF discovery via virtfnN symlinks ─────────────────────────────────────
get_vf_bdf() {
    local idx="$1"   # 0-based index
    local link="/sys/bus/pci/devices/$PF_ADDR/virtfn${idx}"
    [ -L "$link" ] || die "virtfn${idx} not found — VF $((idx+1)) may not have been created"
    basename "$(readlink -f "$link")"
}

# ── Bind a single VF to vfio-pci by BDF ──────────────────────────────────────
bind_vf_to_vfio() {
    local bdf="$1"
    local drv_link="/sys/bus/pci/devices/$bdf/driver"

    modprobe vfio-pci 2>/dev/null || true

    # Unbind from current driver if any
    if [ -L "$drv_link" ]; then
        local cur_drv
        cur_drv=$(basename "$(readlink "$drv_link")")
        if [ "$cur_drv" != "vfio-pci" ]; then
            echo "$bdf" > "/sys/bus/pci/drivers/$cur_drv/unbind" 2>/dev/null || true
        fi
    fi

    echo "vfio-pci" > "/sys/bus/pci/devices/$bdf/driver_override"
    echo "$bdf" > /sys/bus/pci/drivers_probe 2>/dev/null || true
    echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true

    local actual_drv
    actual_drv=$(basename "$(readlink "/sys/bus/pci/devices/$bdf/driver" 2>/dev/null)" 2>/dev/null || echo "unbound")
    [ "$actual_drv" == "vfio-pci" ] || die "Failed to bind $bdf to vfio-pci (driver: $actual_drv)"
    log "VF $bdf bound to vfio-pci"
}

# ── CDI spec generation per bound VF ─────────────────────────────────────────
write_vf_cdi() {
    local vf_idx="$1"   # 1-based VF number for naming
    local bdf="$2"
    local cdi_file="${CDI_DIR}/intel-igpu-tc${vf_idx}.yaml"

    local iommu_link="/sys/bus/pci/devices/$bdf/iommu_group"
    [ -L "$iommu_link" ] || die "No IOMMU group for $bdf — is intel_iommu=on active?"
    local group
    group=$(basename "$(readlink -f "$iommu_link")")
    local vfio_dev="/dev/vfio/$group"
    [ -e "$vfio_dev" ] || die "VFIO device $vfio_dev not found"

    mkdir -p "$CDI_DIR"

    # Read major:minor for /dev/vfio/vfio container device
    local hmaj hmin
    read -r hmaj hmin < <(stat -c "%t %T" /dev/vfio/vfio)
    local vfio_maj=$(( 16#$hmaj )) vfio_min=$(( 16#$hmin ))

    read -r hmaj hmin < <(stat -c "%t %T" "$vfio_dev")
    local grp_maj=$(( 16#$hmaj )) grp_min=$(( 16#$hmin ))

    cat > "$cdi_file" <<EOF
cdiVersion: "0.7.0"
kind: gpu.intel.com/igpu
devices:
  - name: "tc${vf_idx}"
    containerEdits:
      deviceNodes:
        - path: /dev/vfio/vfio
          type: c
          major: ${vfio_maj}
          minor: ${vfio_min}
          fileMode: 432
          permissions: rw
        - path: ${vfio_dev}
          type: c
          major: ${grp_maj}
          minor: ${grp_min}
          fileMode: 432
          permissions: rw
EOF

    log "CDI spec: $cdi_file"
    log "  device: $vfio_dev  (IOMMU group $group, major:minor ${grp_maj}:${grp_min})"
}

# ── Remove all VFs ────────────────────────────────────────────────────────────
remove_sriov_vf() {
    log "Removing all VFs..."
    echo '0' | tee /sys/class/drm/card0/device/sriov_numvfs > /dev/null
    echo "$VENDOR $DEVICE" | tee /sys/bus/pci/drivers/vfio-pci/remove_id > /dev/null 2>&1 || true
    rmmod vfio-pci 2>/dev/null || true
    rm -f "${CDI_DIR}"/intel-igpu-tc*.yaml
    log "VFs removed and CDI specs deleted."
}

# ── Main VF setup ─────────────────────────────────────────────────────────────
setup_sriov_vf() {
    local hw_max
    hw_max=$(cat /sys/class/drm/card0/device/sriov_totalvfs)

    # Resolve M (total to create)
    local total_vfs="${TOTAL_VFS:-$hw_max}"
    [[ "$total_vfs" =~ ^[0-9]+$ ]] || die "TOTAL_VFS must be a positive integer"
    [ "$total_vfs" -le "$hw_max" ] || die "TOTAL_VFS=$total_vfs exceeds hardware max ($hw_max)"

    # Resolve N (to bind)
    local bind_vfs="${BIND_VFS:-$total_vfs}"
    [[ "$bind_vfs" =~ ^[0-9]+$ ]] || die "BIND_VFS must be a positive integer"
    [ "$bind_vfs" -gt 0 ] || die "BIND_VFS must be greater than 0"
    [ "$bind_vfs" -le "$total_vfs" ] || die "BIND_VFS=$bind_vfs cannot exceed TOTAL_VFS=$total_vfs"

    log "Creating $total_vfs VFs, binding $bind_vfs to vfio-pci"

    local current_vfs
    current_vfs=$(cat /sys/class/drm/card0/device/sriov_numvfs)
    if [ "$current_vfs" -gt 0 ]; then
        log "VFs already enabled ($current_vfs). Remove first or use 'remove' command."
        exit 0
    fi

    local drm_drv
    drm_drv=$(lspci -D -k -s "${PF_ADDR#*:}" | grep "Kernel driver in use" | awk -F ':' '{print $2}' | xargs)

    # xe: configure spare resources
    if [ "$drm_drv" == "xe" ]; then
        log "Configuring xe spare resources..."
        echo "$GTT_SPARE_PF"     | tee /sys/kernel/debug/dri/0/gt0/pf/ggtt_spare     > /dev/null
        echo "$CONTEXT_SPARE_PF" | tee /sys/kernel/debug/dri/0/gt0/pf/contexts_spare > /dev/null
        echo "$DOORBELL_SPARE_PF"| tee /sys/kernel/debug/dri/0/gt0/pf/doorbells_spare> /dev/null
    fi

    modprobe i2c-algo-bit 2>/dev/null || warn "Could not load i2c-algo-bit"
    modprobe video        2>/dev/null || warn "Could not load video"

    # Enable auto-provisioning (i915 prelim path, no-op if absent)
    echo '1' | tee /sys/devices/pci0000:00/$PF_ADDR/drm/card0/prelim_iov/pf/auto_provisioning \
        > /dev/null 2>&1 || true

    # Create M VFs
    echo '0' | tee /sys/bus/pci/devices/$PF_ADDR/sriov_drivers_autoprobe > /dev/null
    echo "$total_vfs" | tee /sys/class/drm/card0/device/sriov_numvfs > /dev/null
    echo '1' | tee /sys/bus/pci/devices/$PF_ADDR/sriov_drivers_autoprobe > /dev/null

    # Set per-VF scheduling for all created VFs
    local iov_path=""
    if [ "$drm_drv" == "i915" ]; then
        iov_path="/sys/class/drm/card0/iov"
        [ -d "/sys/class/drm/card0/prelim_iov" ] && iov_path="/sys/class/drm/card0/prelim_iov"
    elif [ "$drm_drv" == "xe" ]; then
        iov_path="/sys/kernel/debug/dri/$PF_ADDR/gt0"
    fi

    if [ -n "$iov_path" ]; then
        for (( i = 1; i <= total_vfs; i++ )); do
            for gt in gt gt0 gt1; do
                if [ -d "${iov_path}/vf$i/$gt" ]; then
                    echo "$VFSCHED_EXECQ"    | tee "${iov_path}/vf$i/$gt/exec_quantum_ms"   > /dev/null
                    echo "$VFSCHED_TIMEOUT"  | tee "${iov_path}/vf$i/$gt/preempt_timeout_us"> /dev/null
                fi
            done
        done
    fi

    # Bind first N VFs to vfio-pci individually and generate CDI specs
    log "Binding $bind_vfs VF(s) to vfio-pci and generating CDI specs..."
    echo ""
    local vfio_devs=()
    for (( i = 0; i < bind_vfs; i++ )); do
        local vf_bdf
        vf_bdf=$(get_vf_bdf "$i")
        bind_vf_to_vfio "$vf_bdf"
        write_vf_cdi "$((i+1))" "$vf_bdf"
        local grp
        grp=$(basename "$(readlink -f "/sys/bus/pci/devices/$vf_bdf/iommu_group")")
        vfio_devs+=("/dev/vfio/$grp")
    done

    echo ""
    log "=== Summary ==="
    log "VFs created  : $total_vfs (of $hw_max supported)"
    log "VFs to vfio  : $bind_vfs"
    log "CDI specs    : ${CDI_DIR}/intel-igpu-tc{1..${bind_vfs}}.yaml"
    echo ""
    log "VFIO devices:"
    for dev in "${vfio_devs[@]}"; do
        echo "  $dev"
    done
    echo ""
    log "CDI device references:"
    for (( i = 1; i <= bind_vfs; i++ )); do
        echo "  gpu.intel.com/igpu=tc${i}"
    done
    echo ""
    log "Setup complete."
}

# ── Entry point ───────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || die "Run as root: sudo $0"

check_gpu_ready || die "GPU not ready"

VENDOR=$(cat /sys/bus/pci/devices/$PF_ADDR/vendor)
DEVICE=$(cat /sys/bus/pci/devices/$PF_ADDR/device)

case "${1:-setup}" in
    setup)   setup_sriov_vf ;;
    remove)  remove_sriov_vf ;;
    *)       echo "Usage: sudo $0 [setup|remove]"
             echo "  TOTAL_VFS=M BIND_VFS=N sudo $0 setup"
             exit 1 ;;
esac

