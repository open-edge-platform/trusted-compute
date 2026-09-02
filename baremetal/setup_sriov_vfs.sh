#!/bin/bash

# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# NUM_VFS — number of VFs to create and bind to vfio-pci
# Empty means use the hardware maximum (sriov_totalvfs)
NUM_VFS="${NUM_VFS:-}"
CDI_DIR="${CDI_DIR:-/etc/cdi}"

GTT_SPARE_PF=$((500 * 1024 * 1024))
CONTEXT_SPARE_PF=9216
DOORBELL_SPARE_PF=32
VFSCHED_EXECQ=25
VFSCHED_TIMEOUT=500000

# PF_ADDR — PCI address (BDF) of the iGPU physical function.
# Override via environment; empty means auto-detect.
PF_ADDR="${PF_ADDR:-}"

# DRM card sysfs path and render node resolved from PF_ADDR
CARD_PATH=""
CARD_NAME=""
CARD_DEV=""
RENDER_DEV=""

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" > /dev/null 2>&1 \
            || die "'$cmd' not found. Install pciutils (e.g., 'apt install pciutils' or 'dnf install pciutils')."
    done
}

# ── PF discovery ──────────────────────────────────────────────────────────────
# Picks the first Intel display/VGA controller exposing sriov_totalvfs.
detect_pf_addr() {
    local dev bdf vendor class
    for dev in /sys/bus/pci/devices/*/; do
        [ -f "${dev}sriov_totalvfs" ] || continue
        vendor=$(cat "${dev}vendor" 2>/dev/null || echo "")
        [ "$vendor" = "0x8086" ] || continue
        class=$(cat "${dev}class" 2>/dev/null || echo "")
        case "$class" in 0x0300*|0x0380*) ;; *) continue ;; esac
        [ -d "${dev}drm" ] || continue
        bdf=$(basename "$dev")
        echo "$bdf"
        return 0
    done
    return 1
}

# ── DRM card resolution ───────────────────────────────────────────────────────
# Matches /sys/class/drm/card*/device against PF_ADDR so multi-GPU hosts and
# non-default enumeration order are handled correctly.
resolve_drm_card() {
    local card node
    for card in /sys/class/drm/card*; do
        [ -e "$card/device" ] || continue
        [ "$(basename "$(readlink -f "$card/device")")" = "$PF_ADDR" ] || continue
        CARD_PATH="$card"
        CARD_NAME=$(basename "$card")
        CARD_DEV="/dev/dri/$CARD_NAME"
        RENDER_DEV=""
        for node in "$card"/device/drm/renderD*; do
            [ -e "$node" ] || continue
            RENDER_DEV="/dev/dri/$(basename "$node")"
            break
        done
        return 0
    done
    return 1
}

# ── xe debugfs directory resolution ───────────────────────────────────────────
# DRM debugfs entries under /sys/kernel/debug/dri are numbered by DRM minor
# (e.g. "0"), not PCI BDF — the BDF is exposed via each entry's "name" file.
XE_DEBUGFS_DIR=""
resolve_xe_debugfs_dir() {
    [ -n "$XE_DEBUGFS_DIR" ] && return 0
    if [ ! -d /sys/kernel/debug/dri ]; then
        warn "/sys/kernel/debug/dri not found — is debugfs mounted? (sudo mount -t debugfs none /sys/kernel/debug)"
        return 1
    fi
    local dir
    for dir in /sys/kernel/debug/dri/*/; do
        [ -f "${dir}name" ] || continue
        if grep -Fq "$PF_ADDR" "${dir}name" 2>/dev/null; then
            XE_DEBUGFS_DIR="${dir%/}"
            return 0
        fi
    done
    warn "Could not find xe debugfs directory for $PF_ADDR under /sys/kernel/debug/dri"
    return 1
}

# ── GPU readiness check ───────────────────────────────────────────────────────
check_gpu_ready() {
    if [ ! -d "/sys/bus/pci/devices/$PF_ADDR" ]; then
        echo "PCI device $PF_ADDR not found"; return 1
    fi

    local drm_driver
    drm_driver=$(lspci -D -k -s "$PF_ADDR" 2>/dev/null \
        | awk -F': *' '/Kernel driver in use/ {print $2; exit}' || true)
    if [ -z "$drm_driver" ]; then
        echo "No kernel driver loaded yet"; return 1
    fi
    if [ "$drm_driver" != "i915" ] && [ "$drm_driver" != "xe" ]; then
        echo "Unexpected driver: $drm_driver (expected i915 or xe)"; return 1
    fi

    if ! resolve_drm_card; then
        echo "No DRM card found for $PF_ADDR"; return 1
    fi
    if [ ! -f "$CARD_PATH/device/sriov_totalvfs" ]; then
        echo "SR-IOV totalvfs file not found"; return 1
    fi

    local total_vfs
    total_vfs=$(cat "$CARD_PATH/device/sriov_totalvfs" 2>/dev/null)
    if [ -z "$total_vfs" ]; then
        echo "Cannot read sriov_totalvfs"; return 1
    fi

    if [ "$drm_driver" = "xe" ] && ! resolve_xe_debugfs_dir; then
        echo "XE driver debugfs not ready"; return 1
    fi

    log "GPU ready (PF: $PF_ADDR, card: $CARD_NAME, driver: $drm_driver, sriov_totalvfs: $total_vfs)"
    return 0
}

# ── VF BDF discovery via virtfnN symlinks ─────────────────────────────────────
get_vf_bdf() {
    local idx="$1"   # 0-based index
    local link="/sys/bus/pci/devices/$PF_ADDR/virtfn${idx}"
    if [ ! -L "$link" ]; then die "virtfn${idx} not found — VF $((idx+1)) may not have been created"; fi
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
    if [ "$actual_drv" != "vfio-pci" ]; then die "Failed to bind $bdf to vfio-pci (driver: $actual_drv)"; fi
    log "VF $bdf bound to vfio-pci"
}

# ── CDI spec generation per bound VF ─────────────────────────────────────────
write_vf_cdi() {
    local vf_idx="$1"   # 1-based VF number for naming
    local bdf="$2"
    local cdi_file="${CDI_DIR}/intel-igpu-tc${vf_idx}.yaml"

    local iommu_link="/sys/bus/pci/devices/$bdf/iommu_group"
    if [ ! -L "$iommu_link" ]; then die "No IOMMU group for $bdf — is intel_iommu=on active?"; fi
    local group
    group=$(basename "$(readlink -f "$iommu_link")")
    local vfio_dev="/dev/vfio/$group"
    if [ ! -e "$vfio_dev" ]; then die "VFIO device $vfio_dev not found"; fi

    mkdir -p "$CDI_DIR"

    # Read major:minor for /dev/vfio/vfio container device
    local hmaj hmin
    read -r hmaj hmin < <(stat -c "%t %T" /dev/vfio/vfio)
    local vfio_maj=$(( 16#$hmaj )) vfio_min=$(( 16#$hmin ))

    read -r hmaj hmin < <(stat -c "%t %T" "$vfio_dev")
    local grp_maj=$(( 16#$hmaj )) grp_min=$(( 16#$hmin ))

    [ -e "$CARD_DEV" ] || die "DRM device node $CARD_DEV not found"
    read -r hmaj hmin < <(stat -c "%t %T" "$CARD_DEV")
    local card_maj=$(( 16#$hmaj )) card_min=$(( 16#$hmin ))

    [ -n "$RENDER_DEV" ] && [ -e "$RENDER_DEV" ] || die "Render node for $PF_ADDR not found"
    read -r hmaj hmin < <(stat -c "%t %T" "$RENDER_DEV")
    local render_maj=$(( 16#$hmaj )) render_min=$(( 16#$hmin ))

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
        - path: ${CARD_DEV}
          type: c
          major: ${card_maj}
          minor: ${card_min}
          fileMode: 432
          permissions: rw
        - path: ${RENDER_DEV}
          type: c
          major: ${render_maj}
          minor: ${render_min}
          fileMode: 432
          permissions: rw
EOF

}

# ── Remove all VFs ────────────────────────────────────────────────────────────
remove_sriov_vf() {
    log "Removing all VFs..."
    echo '0' | tee "$CARD_PATH/device/sriov_numvfs" > /dev/null
    rm -f "${CDI_DIR}"/intel-igpu-tc*.yaml
    log "VFs removed and CDI specs deleted."
}

# ── Main VF setup ─────────────────────────────────────────────────────────────
setup_sriov_vf() {
    local hw_max
    hw_max=$(cat "$CARD_PATH/device/sriov_totalvfs")

    local num_vfs="${NUM_VFS:-$hw_max}"
    case "$num_vfs" in ''|*[!0-9]*) die "NUM_VFS must be a positive integer" ;; esac
    if [ "$num_vfs" -le 0 ]; then die "NUM_VFS must be greater than 0"; fi
    if [ "$num_vfs" -gt "$hw_max" ]; then die "NUM_VFS=$num_vfs exceeds hardware max ($hw_max)"; fi

    local current_vfs
    current_vfs=$(cat "$CARD_PATH/device/sriov_numvfs")
    if [ "$current_vfs" -gt 0 ]; then
        log "VFs already enabled ($current_vfs). Remove first or use 'remove' command."
        exit 0
    fi

    local drm_drv
    drm_drv=$(lspci -D -k -s "$PF_ADDR" 2>/dev/null | awk -F': *' '/Kernel driver in use/ {print $2; exit}' || true)

    # xe: configure spare resources
    if [ "$drm_drv" == "xe" ]; then
        log "Configuring xe spare resources..."
        resolve_xe_debugfs_dir || die "xe debugfs directory not found for $PF_ADDR"
        echo "$GTT_SPARE_PF"     | tee "$XE_DEBUGFS_DIR/gt0/pf/ggtt_spare"     > /dev/null
        echo "$CONTEXT_SPARE_PF" | tee "$XE_DEBUGFS_DIR/gt0/pf/contexts_spare" > /dev/null
        echo "$DOORBELL_SPARE_PF"| tee "$XE_DEBUGFS_DIR/gt0/pf/doorbells_spare"> /dev/null
    fi

    modprobe i2c-algo-bit 2>/dev/null || warn "Could not load i2c-algo-bit"
    modprobe video        2>/dev/null || warn "Could not load video"

    # Enable auto-provisioning (i915 prelim path, no-op if absent)
    echo '1' | tee "$CARD_PATH/prelim_iov/pf/auto_provisioning" \
        > /dev/null 2>&1 || true

    echo '0' | tee "/sys/bus/pci/devices/$PF_ADDR/sriov_drivers_autoprobe" > /dev/null
    if ! echo "$num_vfs" > "$CARD_PATH/device/sriov_numvfs" 2>/dev/null; then
        echo '1' | tee "/sys/bus/pci/devices/$PF_ADDR/sriov_drivers_autoprobe" > /dev/null
        die "Failed to create $num_vfs VFs on $PF_ADDR. The loaded '$drm_drv' driver may not support SR-IOV PF mode (check 'dmesg | grep -i sriov'); an SR-IOV capable i915/xe driver is required."
    fi
    echo '1' | tee "/sys/bus/pci/devices/$PF_ADDR/sriov_drivers_autoprobe" > /dev/null

    # Set per-VF scheduling for all created VFs.
    # i915 nests gt under vf (vf<i>/gt<N>); xe nests vf under gt (gt<N>/vf<i>).
    local iov_path=""
    local xe_gt_first=0
    if [ "$drm_drv" == "i915" ]; then
        iov_path="$CARD_PATH/iov"
        if [ -d "$CARD_PATH/prelim_iov" ]; then iov_path="$CARD_PATH/prelim_iov"; fi
    elif [ "$drm_drv" == "xe" ]; then
        resolve_xe_debugfs_dir || die "xe debugfs directory not found for $PF_ADDR"
        iov_path="$XE_DEBUGFS_DIR"
        xe_gt_first=1
    fi

    if [ -n "$iov_path" ]; then
        for (( i = 1; i <= num_vfs; i++ )); do
            for gt in gt0 gt1; do
                local vf_gt_path
                if [ "$xe_gt_first" -eq 1 ]; then
                    vf_gt_path="${iov_path}/$gt/vf$i"
                else
                    vf_gt_path="${iov_path}/vf$i/$gt"
                fi
                if [ -d "$vf_gt_path" ]; then
                    echo "$VFSCHED_EXECQ"    | tee "${vf_gt_path}/exec_quantum_ms"   > /dev/null
                    echo "$VFSCHED_TIMEOUT"  | tee "${vf_gt_path}/preempt_timeout_us"> /dev/null
                fi
            done
        done
    fi

    # Bind all VFs to vfio-pci and generate CDI specs
    local vfio_devs=()
    for (( i = 0; i < num_vfs; i++ )); do
        local vf_bdf
        vf_bdf=$(get_vf_bdf "$i")
        bind_vf_to_vfio "$vf_bdf"
        write_vf_cdi "$((i+1))" "$vf_bdf"
        local grp
        grp=$(basename "$(readlink -f "/sys/bus/pci/devices/$vf_bdf/iommu_group")")
        vfio_devs+=("/dev/vfio/$grp")
    done

    log "VFIO devices:"
    for dev in "${vfio_devs[@]}"; do log "  VFIO $dev"; done
    log "CDI device references:"
    for (( i = 1; i <= num_vfs; i++ )); do log "  CDI  gpu.intel.com/igpu=tc${i}"; done
}

# ── Entry point ───────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then die "Run as root: sudo $0"; fi

require_cmd lspci

if [ -z "$PF_ADDR" ]; then
    PF_ADDR=$(detect_pf_addr) \
        || die "Could not auto-detect an SR-IOV capable Intel GPU — set PF_ADDR=<domain:bus:dev.func>"
    log "Auto-detected GPU PF: $PF_ADDR"
fi

check_gpu_ready || die "GPU not ready"

case "${1:-setup}" in
    setup)   setup_sriov_vf ;;
    remove)  remove_sriov_vf ;;
    *)       echo "Usage: sudo $0 [setup|remove]"
             echo "  NUM_VFS=N sudo $0 setup"
             echo "  PF_ADDR=0000:00:02.0 sudo $0 setup   # override GPU PF (default: auto-detect)"
             exit 1 ;;
esac

