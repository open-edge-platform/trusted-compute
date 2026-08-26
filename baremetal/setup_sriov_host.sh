#!/bin/bash

# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
KERNEL_BRANCH="${KERNEL_BRANCH:-6.18}"
MAX_VFS="${MAX_VFS:-7}"
CODENAME=""
REPO_LIST="/etc/apt/sources.list.d/intel-rpl.list"
PIN_FILE="/etc/apt/preferences.d/intel-rpl"
GPG_URL="https://download.01.org/intel-linux-overlay/ubuntu/E6FA98203588250569758E97D176E3162086EE4C.gpg"
GPG_DEST="/etc/apt/trusted.gpg.d/rpl.gpg"
GRUB_FILE="/etc/default/grub"
GRUB_BAK="${GRUB_FILE}.bak"

# Supported Ubuntu codenames in the Intel overlay repo
SUPPORTED_CODENAMES=("jammy" "noble")

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Run this script with sudo: sudo $0"
}

# Detect and validate Ubuntu codename against the overlay's supported list
detect_codename() {
    command -v lsb_release &>/dev/null || die "lsb_release not found. Install lsb-release."
    CODENAME=$(lsb_release -cs)
    local supported=0
    for c in "${SUPPORTED_CODENAMES[@]}"; do
        [[ "$c" == "$CODENAME" ]] && supported=1 && break
    done
    if [[ $supported -eq 0 ]]; then
        die "Ubuntu codename '$CODENAME' is not supported by the Intel overlay repo.
Supported: ${SUPPORTED_CODENAMES[*]}
Check https://download.01.org/intel-linux-overlay/ubuntu/dists/ for updates."
    fi
    log "Detected Ubuntu codename: $CODENAME"
}

# ── Step 1: Update base system ────────────────────────────────────────────────
setup_base_update() {
    log "Updating base system..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    log "Base system updated."
}

# ── Step 2: Add Intel overlay repository ─────────────────────────────────────
setup_overlay_repo() {
    if [[ -f "$REPO_LIST" ]]; then
        warn "Repo file $REPO_LIST already exists — skipping."
        return
    fi
    log "Adding Intel Linux overlay repository..."
    tee "$REPO_LIST" > /dev/null <<EOF
deb https://download.01.org/intel-linux-overlay/ubuntu ${CODENAME} main non-free multimedia kernels
deb-src https://download.01.org/intel-linux-overlay/ubuntu ${CODENAME} main non-free multimedia kernels
EOF
    log "Repository added."
}

# ── Step 3: Download GPG key ──────────────────────────────────────────────────
setup_gpg_key() {
    if [[ -f "$GPG_DEST" ]]; then
        warn "GPG key $GPG_DEST already exists — skipping."
        return
    fi
    log "Downloading GPG key..."
    if ! wget -q "$GPG_URL" -O "$GPG_DEST"; then
        rm -f "$GPG_DEST"
        die "Failed to download GPG key from: $GPG_URL
The key URL may have changed. Find the current key at:
  https://download.01.org/intel-linux-overlay/ubuntu/
Update GPG_URL in this script with the new .gpg filename."
    fi
    log "GPG key installed."
}

# ── Step 4: Set APT pin priority ──────────────────────────────────────────────
setup_apt_pin() {
    if [[ -f "$PIN_FILE" ]]; then
        warn "Pin file $PIN_FILE already exists — skipping."
        return
    fi
    log "Setting APT pin priority..."
    tee "$PIN_FILE" > /dev/null <<EOF
Package: *
Pin: release o=intel-iot-linux-overlay-${CODENAME}
Pin-Priority: 2000
EOF
    log "APT pin priority set."
}

# ── Step 5: Install Intel kernel overlay ─────────────────────────────────────
install_kernel() {
    log "Refreshing package index..."
    apt-get update -qq

    local pkg_image="linux-image-${KERNEL_BRANCH}-intel"
    local pkg_headers="linux-headers-${KERNEL_BRANCH}-intel"

    if ! apt-cache show "$pkg_image" &>/dev/null; then
        die "Package $pkg_image not found. Check KERNEL_BRANCH value or repo setup."
    fi

    log "Installing Intel kernel overlay (branch: ${KERNEL_BRANCH}-intel)..."
    # --allow-downgrades: the overlay repo's pinned version may be lower than an already-installed package
    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$pkg_headers" "$pkg_image" \
        || die "Kernel installation failed."
    log "Kernel installed."
}

# ── Step 6: Configure GRUB ────────────────────────────────────────────────────
configure_grub() {
    # Backup
    if [[ ! -f "$GRUB_BAK" ]]; then
        cp "$GRUB_FILE" "$GRUB_BAK"
        log "GRUB backup saved to $GRUB_BAK"
    else
        warn "GRUB backup already exists at $GRUB_BAK — not overwriting."
    fi

    # Kernel parameters
    local max_vfs="${MAX_VFS}"
    [[ "$max_vfs" =~ ^[0-9]+$ ]] || die "MAX_VFS must be a positive integer, got: '$max_vfs'"
    local totalvfs_path="/sys/class/drm/card0/device/sriov_totalvfs"
    if [[ -f "$totalvfs_path" ]]; then
        local hw_max
        hw_max=$(cat "$totalvfs_path")
        if [[ "$max_vfs" -gt "$hw_max" ]]; then
            warn "MAX_VFS=${max_vfs} exceeds hardware maximum (${hw_max}). Clamping to ${hw_max}."
            max_vfs="$hw_max"
        fi
    else
        warn "Cannot read $totalvfs_path — current kernel may not support SR-IOV yet."
        warn "MAX_VFS=${max_vfs} will be written to GRUB; validate after reboot with: cat $totalvfs_path"
    fi

    local params="quiet splash i915.enable_guc=3 i915.max_vfs=${max_vfs} i915.force_probe=* udmabuf.list_limit=8192 intel_iommu=on iommu=pt"
    sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${params}\"/" "$GRUB_FILE"
    log "Kernel parameters set (max_vfs=${max_vfs})."

    # GRUB_DEFAULT — run update-grub first so grub.cfg reflects newly installed kernel
    update-grub

    # Check if the intel kernel entry exists in grub.cfg
    local intel_entry
    intel_entry=$(grep "${KERNEL_BRANCH}-intel" /boot/grub/grub.cfg \
        | grep -v recovery \
        | grep "^[[:space:]]*menuentry" \
        | head -1 \
        | sed "s/.*menuentry '\([^']*\)'.*/\1/" || true)

    if [[ -z "$intel_entry" ]]; then
        warn "Could not find ${KERNEL_BRANCH}-intel in grub.cfg — GRUB_DEFAULT not changed."
    else
        # Check if a higher-versioned non-intel kernel exists at the top level
        local top_level_entries
        top_level_entries=$(grep "^menuentry" /boot/grub/grub.cfg | grep -v recovery || true)
        if echo "$top_level_entries" | grep -q "${KERNEL_BRANCH}-intel"; then
            log "Intel kernel is at top level — GRUB_DEFAULT not changed."
        else
            log "Intel kernel is in submenu. Setting GRUB_DEFAULT..."
            local submenu
            submenu=$(grep -m1 '^submenu' /boot/grub/grub.cfg \
                | sed "s/submenu '\([^']*\)'.*/\1/") \
                || die "Could not find GRUB submenu in /boot/grub/grub.cfg"
            local grub_default="${submenu}>${intel_entry}"
            sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${grub_default}\"|" "$GRUB_FILE"
            log "GRUB_DEFAULT set to: \"${grub_default}\""
            update-grub
        fi
    fi

    log "GRUB updated."
}

# ── Revert ────────────────────────────────────────────────────────────────────
revert_grub() {
    [[ -f "$GRUB_BAK" ]] || die "No GRUB backup found at $GRUB_BAK"
    cp "$GRUB_BAK" "$GRUB_FILE"
    update-grub
    log "GRUB reverted from backup. Reboot to apply."
}

# ── Verify ────────────────────────────────────────────────────────────────────
verify_sriov() {
    log "=== SR-IOV Verification ==="
    echo "Kernel : $(uname -r)"

    local totalvfs_path="/sys/class/drm/card0/device/sriov_totalvfs"
    if [[ -f "$totalvfs_path" ]]; then
        echo "sriov_totalvfs : $(cat "$totalvfs_path")"
    else
        warn "$totalvfs_path not found — GuC may not have loaded. Check: sudo dmesg | grep -i guc"
    fi

    echo "cmdline: $(grep -oE '(i915\.[^ ]+|intel_iommu=[^ ]+|iommu=[^ ]+)' /proc/cmdline | tr '\n' ' ')"
}

# ── Main ──────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo $0 [COMMAND]

Commands:
  install   Run all setup steps (default)
  revert    Restore GRUB from backup
  verify    Check SR-IOV status

Environment variables:
  KERNEL_BRANCH   Intel kernel branch to install (default: 6.18)
  MAX_VFS         Maximum VFs to enable via i915.max_vfs (default: 7)

Examples:
  sudo $0
  sudo KERNEL_BRANCH=6.12 MAX_VFS=4 $0 install
  sudo $0 revert
  sudo $0 verify
EOF
}

main() {
    require_root

    local cmd="${1:-install}"

    case "$cmd" in
        install)
            log "=== Intel SR-IOV Host Setup (kernel: ${KERNEL_BRANCH}-intel, max_vfs: ${MAX_VFS}) ==="
            detect_codename
            setup_base_update
            setup_overlay_repo
            setup_gpg_key
            setup_apt_pin
            install_kernel
            configure_grub
            log "=== Setup complete. Reboot to boot into ${KERNEL_BRANCH}-intel kernel. ==="
            log "Run: sudo reboot"
            ;;
        revert)
            revert_grub
            log "Reboot required to apply GRUB changes. Run: sudo reboot"
            ;;
        verify)
            verify_sriov
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            die "Unknown command: $cmd. Run '$0 help' for usage."
            ;;
    esac
}

main "$@"
