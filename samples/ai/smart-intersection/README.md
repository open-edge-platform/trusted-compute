# Trusted Compute DL Streamer Pipeline Server Sample Applications

## Description

The Smart Intersection is a sample application that unifies the analytics of a traffic intersection.

DL Streamer Pipeline Server is containerized microservice for easy development and deployment of video analytics pipelines. This example demonstrates the deployment of the DL Streamer Pipeline Server in a TC environment, facilitating the isolation of video analytics pipelines.

## Steps to Deploy

### Step 1: Clone the Repository

Clone and navigate to the  Smart Intersection Helm repository:

```bash
# Clone the repository
git clone https://github.com/open-edge-platform/edge-ai-suites.git

# Navigate to the Metro AI Suite directory
cd edge-ai-suites/metro-ai-suite/metro-vision-ai-app-recipe/

```

### Step 2: Replace the Deployment YAML

Inside the `smart-intersection/chart/templates/dlstreamer-pipeline-server/` directory, replace the `https://github.com/open-edge-platform/trusted-compute/tree/main/samples/ai/smart-intersection/deployment.yaml` with the YAML file provided in this repository.

```bash
# Navigate to the templates directory
cd smart-intersection/chart/templates/dlstreamer-pipeline-server/

# Replace the deployment file with your custom version
# Copy the custom deployment.yaml to this location
```

### Step 3: Configure Resource Allocation

We have configured resource allocation to allocate CPU cores and memory. You can adjust the resource requirements according to your specific needs by modifying the resource specifications in the deployment YAML file.

### Step 4: Deploy the Helm Chart

Follow the steps mentioned in the official documentation to run the Helm chart:

[Steps to Deploy the Helm Chart](https://github.com/open-edge-platform/edge-ai-suites/blob/main/metro-ai-suite/metro-vision-ai-app-recipe/smart-intersection/docs/user-guide/how-to-deploy-helm.md)
metro-ai-suite/metro-vision-ai-app-recipe/smart-intersection/docs/user-guide/how-to-deploy-helm.md

## Step 5: Verify DL Streamer Launch

### 1. Verify the DL Streamer Launch in TC

To  Verify the DL Streamer Launch in TC run the following command you will be able to see the VM info.

```bash
ps aux | grep qemu
```

### 2. Check DL Streamer Logs

To monitor the DL Streamer and see the total frames per second (FPS) count, check the logs of the DL Streamer pod:

```bash
kubectl logs <dl-streamer-deployment-name> -n apps
```
