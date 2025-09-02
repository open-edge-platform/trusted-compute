## Trusted Compute k3s Installation on Standalone Ubuntu Edge Node

### Prerequisites

1. **Download Ubuntu 24.04 ISO:**
	- Download the latest Ubuntu 24.04 ISO from the [official Ubuntu website](https://ubuntu.com/download/server).
2. **Install Ubuntu 24.04:**
	- Create a bootable USB and install Ubuntu 24.04 on your edge node.
3. **Enable Secure Boot:**
	- During installation, ensure Secure Boot is enabled in the BIOS/UEFI settings for enhanced security.


---

### Installation Steps

1. **Copy and Unzip Trusted Compute Package:**
	 - Transfer `trusted-compute-installation-package.tgz` to your edge node (using scp, USB, etc.).
	 - Extract the package:
		 ```bash
		 tar -xvf trusted-compute-installation-package.tgz
		 cd trusted-compute-installation-package
		 ```

2. **Install k3s:**
	 - Run the provided script to install k3s:
		 ```bash
		 sudo ./k3s/k3s.sh --install
		 ```

3. **Install Trusted Compute Extension:**
	 - Execute the installation script:
		 ```bash
		 sudo ./install.sh
		 ```

---


### Sample Trusted Workload Deployment
To verify the Trusted Compute setup, deploy a sample nginx pod using Kata Containers.

Create the namespace:

```bash
sudo kubectl create namespace nginx-test
```

Create the nginx pod using a heredoc (the pod uses runtimeClassName: kata-qemu):

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

This will deploy an nginx server as a trusted workload. You can verify the deployment status with:

```bash
sudo kubectl get pods -n nginx-test
sudo kubectl describe pod nginx-default -n nginx-test
sudo kubectl logs nginx-default -n nginx-test
```


Delete the nginx pod and namespace after verification:

```bash
sudo kubectl delete namespace nginx-test
```