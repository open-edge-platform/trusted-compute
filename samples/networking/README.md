# Trusted Compute Networking Sample Applications

## Overview
The workload running in a Trusted Compute environment will involve networking use cases. These samples allow users to validate their setup and provide reference configurations that can be customized to meet specific application requirements:
1. Often, workloads need to communicate with systems outside the edge cluster, necessitating ingress traffic into the cluster. The [Ingress](ingress) sample application demonstrates how to facilitate communication with workloads from outside the edge cluster.
2. Similarly, workloads frequently need to communicate with external services located outside the edge cluster, requiring egress traffic from the cluster. The [Egress](egress) sample application illustrates how to enable external communication.
