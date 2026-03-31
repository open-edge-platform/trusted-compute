#!/usr/bin/env bash

set -euo pipefail

PACKAGE_NAME="trusted-compute-installation-package"
PACKAGE_TAR="${PACKAGE_NAME}.tgz"
PACKAGE_REPO="registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d -t tc-baremetal-setup-XXXXXX)"
PACKAGE_SOURCE="oras"

show_help() {
        cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
    --local-build   Build package locally using make (make build)
    --help          Show this help and exit
    --h             Show this help and exit
    -h              Show this help and exit

Default behavior:
    Pull latest trusted compute installation package from registry using ORAS.
EOF
}

is_k3s_installed() {
    command -v k3s >/dev/null 2>&1 || [[ -x "/usr/local/bin/k3s" ]]
}

is_trusted_compute_present() {
    [[ -d "/opt/kata" || -d "/opt/trustagent" || -d "/opt/verifier" ]]
}

cleanup() {
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local-build)
            PACKAGE_SOURCE="local"
            ;;
        --help|--h|-h)
            show_help
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            echo
            show_help
            exit 1
            ;;
    esac
    shift
done

if [[ "${PACKAGE_SOURCE}" == "oras" ]]; then
    if ! command -v oras >/dev/null 2>&1; then
        echo "Error: oras not found in PATH"
        echo "Install ORAS and re-run this script, or use --local-build."
        exit 1
    fi

    echo "[1/9] Getting latest trusted compute package tag from registry"
    TAG="$(oras repo tags "${PACKAGE_REPO}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)"

    if [[ -z "${TAG}" ]]; then
        echo "Error: Could not resolve latest semantic version tag from ${PACKAGE_REPO}"
        exit 1
    fi

    echo "[2/9] Pulling ${PACKAGE_REPO}:${TAG} with ORAS"
    cd "${TEMP_DIR}"
    oras pull "${PACKAGE_REPO}:${TAG}"
else
    echo "[1/9] Building local installation package with make build"
    cd "${SCRIPT_DIR}"
    make build

    if [[ ! -f "${SCRIPT_DIR}/${PACKAGE_TAR}" ]]; then
        echo "Error: ${PACKAGE_TAR} was not created by make build"
        exit 1
    fi

    echo "[2/9] Copying locally built package into temp directory: ${TEMP_DIR}"
    cp "${SCRIPT_DIR}/${PACKAGE_TAR}" "${TEMP_DIR}/"
fi

if [[ ! -f "${TEMP_DIR}/${PACKAGE_TAR}" ]]; then
    echo "Error: ${PACKAGE_TAR} not found in temp directory"
    exit 1
fi

echo "[3/9] Extracting ${PACKAGE_TAR}"
tar -xvf "${PACKAGE_TAR}"

if [[ ! -d "${TEMP_DIR}/${PACKAGE_NAME}" ]]; then
    echo "Error: Expected directory ${PACKAGE_NAME} not found after extraction"
    exit 1
fi

echo "[4/9] Entering ${PACKAGE_NAME}"
cd "${TEMP_DIR}/${PACKAGE_NAME}"

if is_trusted_compute_present; then
    echo "[5/9] Existing Trusted Compute detected. Uninstalling k3s and cleaning directories"
    sudo ./k3s/k3s.sh --uninstall || true
    sudo rm -rf /opt/kata /opt/trustagent /opt/verifier
else
    echo "[5/9] No existing Trusted Compute directories detected"
fi

if is_k3s_installed; then
    echo "[6/9] k3s is already installed. Skipping k3s installation"
else
    echo "[6/9] Installing k3s"
    sudo ./k3s/k3s.sh --install
fi

echo "[7/9] Installing Trusted Compute Extension"
sudo ./install.sh

echo "[8/9] Deploying sample nginx trusted workload"
sudo kubectl create namespace nginx-test

sudo kubectl -n nginx-test apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: nginx-default
  namespace: nginx-test
spec:
  runtimeClassName: kata-qemu
  containers:
  - name: nginx
    image: nginx:latest
EOF

echo "[9/9] Verifying workload and cleaning up"
sudo kubectl get pods -n nginx-test
sudo kubectl describe pod nginx-default -n nginx-test
sudo kubectl logs nginx-default -n nginx-test
sudo kubectl delete namespace nginx-test

echo "Trusted Compute baremetal setup and sample workload test completed successfully."