---
name: trusted-compute-install
description: Install or uninstall the Intel Trusted Compute stack on bare-metal Ubuntu 24.04, via K3s or Docker. Use when asked to install, deploy, verify, or remove Trusted Compute packages.
metadata:
  {
    "openclaw":
      {
        "emoji": "📦",
        "os": ["linux"],
        "requires": { "bins": ["oras", "mokutil"] }
      }
  }
---

# Trusted Compute Packages Skill

## Purpose

This skill installs the Trusted Compute stack on a bare-metal Ubuntu system.

## Capabilities

- **Install Trusted Compute** (K3s or Docker deployment)

---

## Install Trusted Compute

### Prerequisites

- Ubuntu 24.04 installed
- Secure Boot enabled in BIOS/UEFI
- `oras` CLI installed (see https://oras.land/docs/installation)
- Root/sudo access

### Installation Steps (K3s Deployment)

Execute these steps in order. Wait for each step to complete before proceeding.

#### Step 1: Check Prerequisites

```bash
# Verify Ubuntu version
cat /etc/os-release | grep -E "VERSION_ID|NAME"

# Check if oras is installed
which oras || echo "ERROR: oras not installed - see https://oras.land/docs/installation"

# Check Secure Boot status
mokutil --sb-state
```

#### Step 2: Get Latest Trusted Compute Package Version

```bash
TAG=$(oras repo tags registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1) && echo "Latest version: $TAG"
```

#### Step 3: Download the Trusted Compute Package

```bash
oras pull registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package:$TAG
```

#### Step 4: Extract the Installation Package

```bash
tar -xvf trusted-compute-installation-package.tgz
ls -la trusted-compute-installation-package/
```

#### Step 5: Change to Package Directory

```bash
cd trusted-compute-installation-package
pwd
```

#### Step 6: Install K3s

```bash
sudo ./k3s/k3s.sh --install
```

#### Step 7: Verify K3s Cluster is Ready

```bash
sudo kubectl get nodes
# Wait until node shows "Ready" status
```

#### Step 8: Install Trusted Compute Components

```bash
sudo ./install.sh --k3s
```

#### Step 9: Verify Installation

```bash
# Check all TC pods are running
sudo kubectl get pods -A | grep -E "trust|attestation|kata"

# Check Helm releases
sudo helm list -A

# Check runtime classes
sudo kubectl get runtimeclass
```

### Installation Steps (Docker Deployment)

Alternative deployment using Docker instead of K3s.

#### Step 1-5: Same as K3s

Follow Steps 1-5 from K3s deployment above.

#### Step 6: Install Docker (if not installed)

```bash
# Check Docker version (must be 29.4.x, NOT 29.5+)
docker --version

# If not installed, follow: https://docs.docker.com/engine/install/ubuntu/
```

#### Step 7: Install Trusted Compute with Docker

```bash
sudo ./install.sh --docker
```

#### Step 8: Verify Docker Installation

```bash
# Check Docker is configured with Kata runtime
docker info | grep -i runtime
```

---

## Output Format

```
TRUSTED COMPUTE INSTALLATION
  Step 1: Prerequisites ✓
    - Ubuntu: 24.04
    - oras: installed
    - Secure Boot: Enabled
  Step 2: Package Version ✓
    - Latest: 1.5.0
  Step 3: Download ✓
  Step 4: Extract ✓
  Step 5: Directory ✓
  Step 6: K3s Install ✓
  Step 7: K3s Ready ✓
    - Node: <hostname> Ready
  Step 8: TC Install ✓
  Step 9: Verification ✓
    - Pods: Running
    - RuntimeClass: kata-qemu available
```

## Uninstallation

### K3s Deployment

```bash
cd trusted-compute-installation-package
sudo ./uninstall.sh --k3s
```

### Docker Deployment

```bash
cd trusted-compute-installation-package
sudo ./uninstall.sh --docker
```

## Dependencies

- `oras` CLI (for downloading packages)
- Root/sudo access