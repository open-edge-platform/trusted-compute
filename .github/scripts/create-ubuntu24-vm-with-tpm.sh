#!/bin/bash

#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Script to create a Ubuntu 24 VM with TPM (swtpm) and Secure Boot enabled
# Usage: ./.github/scripts/create-ubuntu24-vm-with-tpm.sh [vm-name] [vcpus] [memory-gb] [disk-gb]

set -e

# Configuration
VM_NAME="${1:-ubuntu24-trusted-compute}"
VCPUS="${2:-4}"
MEMORY_GB="${3:-8}"
DISK_GB="${4:-50}"
DISK_SIZE="${DISK_GB}G"
VM_USERNAME="user"
VM_PASSWORD="user"
if command -v mkpasswd &>/dev/null; then
    VM_HASHED_PASSWORD="$(mkpasswd -m sha-512 "$VM_PASSWORD")"
else
    VM_HASHED_PASSWORD="$(openssl passwd -6 "$VM_PASSWORD")"
fi
UBUNTU_CLOUD_IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
SSH_KEY_NAME="${VM_NAME}-id_ed25519"

# Paths
LIBVIRT_DIR="/var/lib/libvirt/images"
VM_DIR="${LIBVIRT_DIR}/${VM_NAME}"
DISK_PATH="${VM_DIR}/disk.qcow2"
OVMF_VARS="${VM_DIR}/OVMF_VARS.fd"
OVMF_VARS_TEMPLATE=""
CLOUD_INIT_ISO="${VM_DIR}/seed.iso"
SSH_KEY_DIR="${VM_DIR}/ssh"
SSH_PRIVATE_KEY="${SSH_KEY_DIR}/${SSH_KEY_NAME}"
SSH_PUBLIC_KEY="${SSH_PRIVATE_KEY}.pub"
VM_AUTHORIZED_KEY=""
NESTED_CPU_FEATURE=""

# Detect OVMF firmware path (try multiple known locations for Ubuntu 24.04)
detect_ovmf_code() {
    for path in \
        /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
        /usr/share/OVMF/OVMF_CODE.secboot.fd \
        /usr/share/OVMF/OVMF_CODE_4M.ms.fd \
        /usr/share/OVMF/OVMF_CODE.ms.fd \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd; do
        if [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

detect_ovmf_vars() {
    for path in \
        /usr/share/OVMF/OVMF_VARS_4M.ms.fd \
        /usr/share/OVMF/OVMF_VARS.ms.fd \
        /usr/share/OVMF/OVMF_VARS_4M.fd \
        /usr/share/OVMF/OVMF_VARS.fd; do
        if [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

OVMF_CODE="$(detect_ovmf_code || true)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for required tools
  for tool in qemu-system-x86_64 virsh ssh-keygen; do
        if ! command -v $tool &> /dev/null; then
            log_error "$tool is not installed"
            exit 1
        fi
    done

    if grep -qw vmx /proc/cpuinfo; then
      NESTED_CPU_FEATURE="vmx"
    elif grep -qw svm /proc/cpuinfo; then
      NESTED_CPU_FEATURE="svm"
    else
      log_error "Host CPU does not expose vmx or svm; nested virtualization is required for Kata inside the DUT VM"
      exit 1
    fi
    log_info "Nested virtualization CPU feature detected: $NESTED_CPU_FEATURE"
    
    # Check for OVMF firmware with Secure Boot support
    if [[ -z "$OVMF_CODE" ]]; then
        log_info "Installing ovmf package..."
        sudo apt-get update -qq
        sudo apt-get install -y ovmf
        OVMF_CODE="$(detect_ovmf_code || true)"
    fi
    
    if [[ -n "$OVMF_CODE" ]]; then
        log_info "Found OVMF firmware at: $OVMF_CODE"
    else
        log_error "OVMF firmware with Secure Boot support not found after installation"
        exit 1
    fi
    
    # Check for swtpm package and install when missing
    if ! command -v swtpm &> /dev/null; then
      log_info "Installing swtpm package..."
      sudo apt-get update -qq
      sudo apt-get install -y swtpm
    fi

    # Check for cloud-init ISO builder
    if ! command -v cloud-localds &> /dev/null; then
      log_info "Installing cloud-image-utils package..."
      sudo apt-get update -qq
      sudo apt-get install -y cloud-image-utils
    fi

    log_info "Restarting libvirtd to ensure swtpm integration is active..."
    if command -v systemctl &> /dev/null; then
      sudo systemctl restart libvirtd || sudo systemctl restart libvirt-daemon
    else
      sudo service libvirtd restart || sudo service libvirt-daemon restart
    fi
    
    log_info "All prerequisites are met"
}

# Create VM directories
setup_directories() {
    log_info "Setting up directories..."
    sudo mkdir -p "$VM_DIR"
  sudo chmod 755 "$VM_DIR"
}

# Generate an SSH key pair and use the public key for cloud-init authorized keys
generate_ssh_key_pair() {
  log_info "Generating VM SSH key pair..."
  sudo mkdir -p "$SSH_KEY_DIR"

  if [[ ! -f "$SSH_PRIVATE_KEY" ]]; then
    sudo ssh-keygen -t ed25519 -N "" -f "$SSH_PRIVATE_KEY" -C "${VM_USERNAME}@${VM_NAME}" >/dev/null
    log_info "SSH private key created at $SSH_PRIVATE_KEY"
  else
    log_info "Using existing SSH private key at $SSH_PRIVATE_KEY"
  fi

  if [[ ! -f "$SSH_PUBLIC_KEY" ]]; then
    log_error "SSH public key not found at $SSH_PUBLIC_KEY"
    exit 1
  fi

  VM_AUTHORIZED_KEY="$(sudo cat "$SSH_PUBLIC_KEY")"
}

# Download Ubuntu 24.04 cloud image and resize to requested disk size
create_disk() {
    local cached_image="${LIBVIRT_DIR}/noble-server-cloudimg-amd64.img"

    if [[ ! -f "$cached_image" ]]; then
        log_info "Downloading Ubuntu 24.04 cloud image..."
        sudo wget -q --show-progress "$UBUNTU_CLOUD_IMAGE_URL" -O "$cached_image" || {
            log_error "Failed to download Ubuntu cloud image"
            exit 1
        }
        log_info "Cloud image downloaded to $cached_image"
    else
        log_info "Using cached Ubuntu cloud image: $cached_image"
    fi

    log_info "Copying cloud image as VM disk..."
    sudo cp "$cached_image" "$DISK_PATH"

    log_info "Resizing disk to ${DISK_SIZE}..."
    sudo qemu-img resize "$DISK_PATH" "$DISK_SIZE"
    log_info "Disk ready at $DISK_PATH (${DISK_SIZE})"
}

# Create cloud-init seed ISO for default VM credentials
create_cloud_init_seed() {
    local user_data_file="${VM_DIR}/user-data"
    local meta_data_file="${VM_DIR}/meta-data"

    log_info "Creating cloud-init seed with default credentials (${VM_USERNAME}/${VM_PASSWORD})..."

    cat > /tmp/user-data-template << EOF
#cloud-config
users:
  - default
  - name: %VM_USERNAME%
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    hashed_passwd: '%VM_HASHED_PASSWORD%'
    ssh_authorized_keys:
      - %VM_AUTHORIZED_KEY%
chpasswd:
  expire: false
ssh_pwauth: true
EOF

    cat > /tmp/meta-data-template << EOF
instance-id: %VM_NAME%-instance
local-hostname: %VM_NAME%
EOF

    sed -e "s|%VM_USERNAME%|$VM_USERNAME|g" \
        -e "s|%VM_HASHED_PASSWORD%|$VM_HASHED_PASSWORD|g" \
        -e "s|%VM_AUTHORIZED_KEY%|$VM_AUTHORIZED_KEY|g" \
        /tmp/user-data-template | sudo tee "$user_data_file" > /dev/null

    sed -e "s|%VM_NAME%|$VM_NAME|g" \
        /tmp/meta-data-template | sudo tee "$meta_data_file" > /dev/null

    sudo cloud-localds "$CLOUD_INIT_ISO" "$user_data_file" "$meta_data_file"
    sudo chmod 644 "$CLOUD_INIT_ISO"
    log_info "Cloud-init seed ISO created at $CLOUD_INIT_ISO"
}

# Setup UEFI with Secure Boot
setup_uefi() {
    log_info "Setting up UEFI with Secure Boot..."
    
    if [[ -n "$OVMF_CODE" ]] && [[ -f "$OVMF_CODE" ]]; then
        # Find and copy OVMF_VARS template
        local ovmf_vars_template
        ovmf_vars_template="$(detect_ovmf_vars || true)"
        if [[ -n "$ovmf_vars_template" ]]; then
            OVMF_VARS_TEMPLATE="$ovmf_vars_template"
            sudo cp "$ovmf_vars_template" "$OVMF_VARS"
            sudo chmod 644 "$OVMF_VARS"
            log_info "UEFI Secure Boot firmware configured (code: $OVMF_CODE, vars template: $ovmf_vars_template)"
        else
            log_warn "OVMF_VARS template not found"
        fi
    else
        log_warn "OVMF firmware not available - will use default BIOS"
    fi
}

# Create libvirt domain XML
create_domain_xml() {
    local xml_file="${VM_DIR}/domain.xml"

    if [[ -z "$OVMF_VARS_TEMPLATE" ]]; then
        OVMF_VARS_TEMPLATE="$(detect_ovmf_vars || true)"
    fi
    
    log_info "Creating libvirt domain XML..."
    
    cat > /tmp/domain-template.xml << 'EOF'
<domain type='kvm'>
  <name>%VM_NAME%</name>
  <memory unit='GiB'>%MEMORY_GB%</memory>
  <currentMemory unit='GiB'>%MEMORY_GB%</currentMemory>
  <vcpu placement='static'>%VCPUS%</vcpu>
  <cpu mode='host-passthrough' check='none' migratable='on'>
    <feature policy='require' name='%NESTED_CPU_FEATURE%'/>
  </cpu>
  
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' type='pflash'>%OVMF_CODE%</loader>
    <nvram template='%OVMF_VARS_TEMPLATE%'>%OVMF_VARS%</nvram>
    <boot dev='hd'/>
    <bootmenu enable='yes' timeout='3000'/>
  </os>

  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>

  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>

  <pm>
    <suspend-to-mem enabled='yes'/>
    <suspend-to-disk enabled='yes'/>
  </pm>

  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>

    <!-- Disk -->
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='%DISK_PATH%'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <!-- Cloud-init seed (NoCloud) -->
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='%CLOUD_INIT_ISO%'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>

    <!-- TPM 2.0 (libvirt-managed swtpm) -->
    <tpm model='tpm-tis'>
      <backend type='emulator' version='2.0'/>
    </tpm>

    <!-- Network -->
    <interface type='network'>
      <mac address='52:54:00:12:34:56'/>
      <source network='default'/>
      <model type='virtio'/>
    </interface>

    <!-- Serial -->
    <serial type='pty'>
      <target port='0'/>
    </serial>

    <!-- Console -->
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>

    <!-- VNC Display -->
    <graphics type='vnc' port='-1' autoport='yes'>
      <listen type='address' address='127.0.0.1'/>
    </graphics>

    <!-- vhost-vsock: required by Kata Containers for guest agent communication -->
    <vsock model='virtio'>
      <cid auto='yes'/>
    </vsock>

  </devices>
</domain>
EOF

    # Replace placeholders
    sed -e "s|%VM_NAME%|$VM_NAME|g" \
        -e "s|%MEMORY_GB%|$MEMORY_GB|g" \
        -e "s|%VCPUS%|$VCPUS|g" \
      -e "s|%NESTED_CPU_FEATURE%|$NESTED_CPU_FEATURE|g" \
        -e "s|%DISK_PATH%|$DISK_PATH|g" \
        -e "s|%CLOUD_INIT_ISO%|$CLOUD_INIT_ISO|g" \
        -e "s|%OVMF_CODE%|$OVMF_CODE|g" \
        -e "s|%OVMF_VARS%|$OVMF_VARS|g" \
        -e "s|%OVMF_VARS_TEMPLATE%|$OVMF_VARS_TEMPLATE|g" \
        /tmp/domain-template.xml | sudo tee "$xml_file" > /dev/null
    
    log_info "Domain XML created at $xml_file"
}

# Define and create VM
create_vm() {
    log_info "Creating VM with libvirt..."
    
    local xml_file="${VM_DIR}/domain.xml"
    
    # Define the domain
    if ! sudo virsh define "$xml_file"; then
        log_error "Failed to define VM domain from $xml_file"
        exit 1
    fi
    
    log_info "VM domain created: $VM_NAME"
}

# Install Ubuntu using virt-install (requires ISO)
install_ubuntu() {
    log_info "Installing Ubuntu 24 (Noble)..."
    log_info "Downloading Ubuntu 24 ISO..."
    
    local iso_url="https://releases.ubuntu.com/noble/ubuntu-24.04-live-server-amd64.iso"
    local iso_path="${VM_DIR}/ubuntu-24.04.iso"
    
    if [[ ! -f "$iso_path" ]]; then
        sudo wget -q "$iso_url" -O "$iso_path" || {
            log_error "Failed to download Ubuntu ISO"
            exit 1
        }
    fi
    
    log_info "Starting VM installation..."
    log_warn "Please complete the Ubuntu installation in the VM console"
    log_info "VM will be accessible via VNC or virsh console"
    
    # Start the VM for installation
    sudo virsh start "$VM_NAME" || true
    
    log_info "VM started. Connect using:"
    echo "  virsh console $VM_NAME"
    echo "  Or use VNC client to connect to localhost:5900 (or the assigned port)"
}

# Main execution
main() {
    log_info "Starting VM creation process..."
    log_info "VM Name: $VM_NAME"
    log_info "vCPUs: $VCPUS"
    log_info "Memory: ${MEMORY_GB}GB"
    log_info "Disk: $DISK_SIZE"
    
    check_prerequisites
    setup_directories
    generate_ssh_key_pair
    create_disk
    create_cloud_init_seed
    setup_uefi
    create_domain_xml
    create_vm
    
    log_info "VM creation completed successfully!"
    log_info "To start the VM installation:"
    echo ""
    echo "  sudo virsh start $VM_NAME"
    echo ""
    echo "To connect to the VM:"
    echo "  sudo virsh console $VM_NAME"
    echo ""
    echo "To check VM status:"
    echo "  sudo virsh list --all"
    echo ""
    echo "To verify TPM inside VM, run:"
    echo "  sudo virsh console $VM_NAME"
    echo "  # Inside VM:"
    echo "  tpm2_getcap handles-persistent"
    echo ""
    echo "Default VM credentials (cloud-init):"
    echo "  username: $VM_USERNAME"
    echo "  password: $VM_PASSWORD"
    echo ""
    echo "SSH key pair for VM access:"
    echo "  private key: $SSH_PRIVATE_KEY"
    echo "  public key: $SSH_PUBLIC_KEY"
    echo ""
}

# Run main function
main "$@"
