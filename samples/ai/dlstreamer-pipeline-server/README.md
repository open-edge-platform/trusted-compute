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

## Step 5: Verify DL Streamer Launch

### 1. Launch Workload

You can launch any workload by following the instructions provided in the **Run Default Sample** section of the [official documentation](https://github.com/open-edge-platform/edge-ai-libraries/tree/main/microservices/dlstreamer-pipeline-server#run-default-sample).

### 2. Check DL Streamer Logs

To monitor the DL Streamer and see the total frames per second (FPS) count, check the logs of the DL Streamer pod:

```bash
kubectl logs <dl-streamer-deployment-name> -n apps
```
You can verify the number of FPS and the number of streams running inside the DL Streamer pipeline.

<img width="1204" height="259" alt="image" src="https://github.com/user-attachments/assets/9e650f27-a886-43f3-b39c-3ee92eddf5d5" />
