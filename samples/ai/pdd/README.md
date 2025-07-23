# Trusted Compute PDD Sample Applications

## Description

The Manufacturing AI Suite Pallet Defect Detection is an AI-powered solution designed to automatically detect defects in pallets using computer vision and machine learning techniques. This example demonstrates the deployment of the Pallet Defect Detection pipeline using DL Streamer Pipeline Server in a containerized environment, enabling efficient quality control in manufacturing processes.

## Steps to Deploy

### Step 1: Clone the Repository

Clone the specific tag and navigate to the Manufacturing AI Suite Pallet Defect Detection repository:

```bash
git clone --branch v1.0.0 https://github.com/open-edge-platform/edge-ai-suites.git
cd edge-ai-suites/manufacturing-ai-suite/pallet-defect-detection/helm/templates
```

### Step 2: Replace the DL Streamer Pipeline Server YAML

Replace the `dlstreamer-pipeline-server.yaml` with the custom YAML file provided in this repository `https://github.com/open-edge-platform/trusted-compute/tree/main/samples/ai/dlstreamer-pipeline-server/dlstreamer-pipeline-server.yaml`:

```bash
# Copy the custom dlstreamer-pipeline-server.yaml from thsi source
cp <tc_repo>/dlstreamer-pipeline-server.yaml ./dlstreamer-pipeline-server.yaml
```

### Step 3: Configure Resource Allocation

We have configured resource allocation to allocate CPU cores and memory specifically optimized for pallet defect detection workloads. You can adjust the resource requirements according to your specific infrastructure needs by modifying the resource specifications in the deployment YAML file.

https://github.com/open-edge-platform/trusted-compute/blob/main/samples/ai/pdd/dlstreamer-pipeline-server.yaml#L54

### Step 4: Deploy the Helm Chart

Deploy the Pallet Defect Detection application in the Kubernetes cluster using Helm. Follow the official deployment instructions:

[Deploy Pallet Defect Detection in the Kubernetes Node](https://github.com/open-edge-platform/edge-ai-suites/tree/v1.0.0/manufacturing-ai-suite/pallet-defect-detection/helm#deploy-pallet-defect-detection-in-the-kubernetes-node)
