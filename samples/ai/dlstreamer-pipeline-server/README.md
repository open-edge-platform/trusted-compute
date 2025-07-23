# Trusted Compute DL Streamer Pipeline Server Sample Applications

## Description

DL Streamer Pipeline Server is containerized microservice for easy development and deployment of video analytics pipelines. This example demonstrates the deployment of the DL Streamer Pipeline Server in a TC environment, facilitating the isolation of video analytics pipelines.

## Steps to Deploy

### Step 1: Clone the Repository

Clone and navigate to the DL Streamer Pipeline Server Helm repository:

```bash
git clone https://github.com/open-edge-platform/edge-ai-libraries.git
cd edge-ai-libraries/microservices/dlstreamer-pipeline-server/helm
```

### Step 2: Replace the Deployment YAML

Inside the `templates` directory, replace the `https://github.com/open-edge-platform/trusted-compute/tree/main/samples/ai/dlstreamer-pipeline-server/dlstreamer-pipeline-server-deployment.yaml` with the YAML file provided in this repository.

```bash
# Navigate to the templates directory
cd templates

# Replace the deployment file with your custom version
# Copy your custom dlstreamer-pipeline-server-deployment.yaml to this location
```

### Step 3: Configure Resource Allocation

We have configured resource allocation to allocate CPU cores and memory. You can adjust the resource requirements according to your specific needs by modifying the resource specifications in the deployment YAML file.

https://github.com/open-edge-platform/trusted-compute/blob/main/samples/ai/dlstreamer-pipeline-server/dlstreamer-pipeline-server-deployment.yaml#L35

### Step 4: Deploy the Helm Chart

Follow the steps mentioned in the official documentation to run the Helm chart:

[Steps to Deploy the Helm Chart](https://github.com/open-edge-platform/edge-ai-libraries/tree/main/microservices/dlstreamer-pipeline-server/helm#steps-to-deploy-the-helm-chart)
