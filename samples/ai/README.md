# Trusted Compute AI Sample Applications

## Overview
The workload running in a Trusted Compute environment will involve AI use cases. These samples allow AI Microservices from [Edge AI Libraries](https://github.com/open-edge-platform/edge-ai-libraries/tree/main/microservices) and AI Application from [Edge AI Suites](https://github.com/open-edge-platform/edge-ai-suites) to execute in Trusted Compute environment.
1. [DL Streamer Pipeline Server](dlstreamer-pipeline-server) is containerized microservice for easy development and deployment of video analytics pipelines. This example demonstrates the deployment of the DL Streamer Pipeline Server in a TC environment, facilitating the isolation of video analytics pipelines.
2. [Pallet Defect Detection](pdd) Application enables real-time pallet condition monitoring by running inference workflows across multiple AI models. This example demonstrates the deployment of the PDD in a TC environment, facilitating the isolation of PDD pipelines.
3. [Smart City Intersection](smart-intersection) The application integrates analytics from multiple traffic cameras to create a comprehensive intersection overview, facilitating cross-camera object tracking, motion vector analysis (including speed and direction), and 3D spatial understanding of object interactions.
4. [Langfuse Integration with OpenClaw](langfuse-openclaw) deploys a self-hosted Langfuse instance, installs the Langfuse bridge plugin, and configures an existing OpenClaw gateway to export traces.
