## Trusted Compute Installation on Standalone Ubuntu Edge Node

The installation script supports two deployment options:

| Option | Description |
|------|-------------|
| **K3s** | Deploys Trusted Compute components as Helm-managed workloads inside a K3s cluster |
| **Docker** | Deploys Trusted Compute Components directly via Docker Compose |

---

### Table of Contents

| # | Section |
|---|---------|
| 1 | [Prerequisites](#1-prerequisites) |
| 2 | [Download the Trusted Compute Package](#2-download-the-trusted-compute-package) |
| 3 | [K3s Option](#3-k3s-option) |
|   | &nbsp;&nbsp;3.1 [Installation](#31-installation) |
|   | &nbsp;&nbsp;3.2 [Sample Trusted Workload Deployment](#32-sample-trusted-workload-deployment) |
|   | &nbsp;&nbsp;3.3 [Uninstallation](#33-uninstallation) |
| 4 | [Docker Option](#4-docker-option) |
|   | &nbsp;&nbsp;4.1 [Installation](#41-installation) |
|   | &nbsp;&nbsp;4.2 [Sample Trusted Workload Deployment](#42-sample-trusted-workload-deployment) |
|   | &nbsp;&nbsp;4.3 [Uninstallation](#43-uninstallation) |

---

### 1. Prerequisites

1. **Download Ubuntu 24.04 ISO:**
	- Download the latest Ubuntu 24.04 ISO from the [official Ubuntu website](https://ubuntu.com/download/server).
2. **Install Ubuntu 24.04:**
	- Create a bootable USB and install Ubuntu 24.04 on your edge node.
3. **Enable Secure Boot:**
	- During installation, ensure Secure Boot is enabled in the BIOS/UEFI settings for enhanced security.

> **Note:** Both K3s and Docker installations are mutually exclusive. If one is already installed, the script will prompt you to uninstall it first before proceeding with the other.

---

### 2. Download the Trusted Compute Package

1. **Get the Latest Tag and Download (using ORAS):**
	```bash
	TAG=$(oras repo tags registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
	oras pull registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package:$TAG
	```
	- Ensure `oras` is available — see the [oras installation guide](https://oras.land/docs/installation).

2. **Extract the Package:**
	- Transfer `trusted-compute-installation-package.tgz` to your edge node (using scp, USB, etc.), then extract:
	```bash
	tar -xvf trusted-compute-installation-package.tgz
	cd trusted-compute-installation-package
	```

---

### 3. K3s Option

#### 3.1 Installation

1. **Install K3s** (if not already installed):

	Use the provided script:
	```bash
	sudo ./k3s/k3s.sh --install
	```
	Or install manually by following the [K3s Quick Start Guide](https://docs.k3s.io/quick-start).

2. **Run the installation script:**
	```bash
	sudo ./install.sh --k3s
	```
	Or run without arguments and select **K3s** in the interactive option selector:
	```bash
	sudo ./install.sh
	```

---

#### 3.2 Sample Trusted Workload Deployment

1. **Create the namespace:**
	```bash
	sudo kubectl create namespace nginx-test
	```

2. **Deploy a sample nginx pod** (uses `runtimeClassName: kata-qemu`):
	```bash
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
	```

3. **Verify the deployment status:**
	```bash
	sudo kubectl get pods -n nginx-test
	sudo kubectl describe pod nginx-default -n nginx-test
	sudo kubectl logs nginx-default -n nginx-test
	```

4. **Delete the pod and namespace after verification:**
	```bash
	sudo kubectl delete namespace nginx-test
	```

---

#### 3.3 Uninstallation

1. **Run the uninstallation script:**
	```bash
	sudo ./uninstall.sh --k3s
	```
	Or run without arguments and select **K3s** in the interactive option selector.

---

### 4. Docker Option

#### 4.1 Installation

1. **Install Docker Engine** (if not already installed):

	Follow the official guide for Ubuntu:
	[https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)

2. **Install Docker Compose v2 plugin** (if not already installed):

	Follow the official guide: [https://docs.docker.com/compose/install/linux/](https://docs.docker.com/compose/install/linux/)

3. **Run the installation script:**
	```bash
	sudo ./install.sh --docker
	```
	Or run without arguments and select **Docker** in the interactive option selector:
	```bash
	sudo ./install.sh
	```

---

#### 4.2 Sample Trusted Workload Deployment

Once Trusted Compute is installed, run workload by defining kata-runtime for hardware-isolated Trusted Compute execution.

1. **Run Workload with the Kata runtime:**
	```bash
	docker run -d --name nginx-test --runtime io.containerd.kata.v2 -p 80:80 nginx:latest
	```

2. **Verify the workload is running:**
	```bash
	docker ps | grep nginx-test
	```

3. **Verify it's using the Kata runtime:**
	```bash
	docker inspect nginx-test --format '{{.HostConfig.Runtime}}'
	```
	Output should be: `io.containerd.kata.v2`

4. **Stop and remove the workload after verification:**
	```bash
	docker stop nginx-test
	docker rm nginx-test
	```

**Alternatively, use Docker Compose to run workload with the Kata runtime:**

5. **Create an `nginx.yaml` file:**
	```bash
	cat > nginx.yaml <<'EOF'
	services:
	  nginx:
	    image: nginx:latest
	    container_name: nginx-test
	    ports:
	      - "80:80"
	    runtime: io.containerd.kata.v2
	EOF
	```

6. **Start the workload with Docker Compose:**
	```bash
	docker compose -f nginx.yaml up -d
	```

7. **Verify the workload is running:**
	```bash
	docker ps -a | grep nginx-test
	```

8. **Check the workload logs:**
	```bash
	docker logs nginx-test
	```

9. **Stop and remove the workload:**
	```bash
	docker compose -f nginx.yaml down
	```

---

#### 4.3 Uninstallation

1. **Run the uninstallation script:**
	```bash
	sudo ./uninstall.sh --docker
	```
	Or run without arguments and select **Docker** in the interactive option selector.
