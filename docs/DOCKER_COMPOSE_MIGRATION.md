# Kubernetes to Docker Compose Migration Plan

## Overview

This document outlines the migration plan for porting the current Kubernetes Helm-based deployment to Docker Compose for the Trusted Compute platform.

## Trusted compute architecture components

### 1. **Attestation Verifier Stack**
- **CMS** (Certificate Management Service)
- **AAS** (Authentication & Authorization Service) + PostgreSQL DB
- **HVS** (Host Verification Service) + PostgreSQL DB  
- **NATS** (Message broker)
- Multiple init containers and job orchestration
- Complex dependency chain with certificate management

### 2. **Trust Agent**
- DaemonSet with privileged access to host resources
- Multiple init containers for dependency waiting
- Complex volume mounts for host access (`/dev/tpmrm0`, `/sys/firmware`, `/dev/mem`)
- IMA scanning sidecar container
- Requires root privileges and host filesystem access

### 3. **Attestation Manager**
- Single deployment with dependency on HVS
- Manages node attestation and polling
- Interacts with Kubernetes API for node management

## Migration Strategy

### Container Images
```
# Intel Registry Images
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-manager
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/authservice
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/cms
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/hvs
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/tagent
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/init-wait
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/aas-manager
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/nats-init
registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/kata-deploy

# External Images
postgres
nats
debian:bullseye-slim
alpine/kubectl
ghcr.io/containerd/nri/plugins/device-injector
quay.io/confidential-containers/operator
```

## **Kubernetes Resource Reference**

### **Attestation K8S Secrets**

| K8S Secret | Source | Consumer |
|------------|--------|----------|
| `hvsdb-credentials` | db-secrets (Created by HVS charts) | HVS DB, HVS |
| `aasdb-credentials` | db-secrets (Created by AAS charts) | AAS DB, AAS |
| `aas-credentials` | Secrets (Created by AAS charts) | AAS |
| `hvs-credentials` | Secrets (Created by HVS charts) | HVS |
| `trustagent-credentials` | Secret (Created by trustagent Charts) | Trust Agent |
| `hvs-aas-json` | aas-mgr-secrets (Created by HVS Charts) | hvs-aas-manager (Job) |
| `global-admin-generator-aas-json` | Secret (Created by global-admin-generator charts) | global-admin-generator (Job) |
| `global-admin-generator-credentials` | Secret (Created by global-admin-generator charts) | Attestation Manager Pod |
| `trustagent-aas-manager-aas-json` | Secret (Created by trustagent-aas-manager charts) | trustagent-aas-manager (Job) |
| `nats-init-aas-json` | Secret (Created by nats-inits charts) | nats-init-aas-manager (Job) |
| `aasdb-certs` | aasdb-cert-generator (Job) | Auth Service |
| `hvsdb-certs` | hvsdb-cert-generator (Job) | HVS DB Deployment |
| `cms-tls-cert-sha384` | cms-init (Job) | AAS, HVS, Trustagent |
| `aas-token` | cms-init (Job) | AAS |
| `nats-init-bearer-token` | nats-init-wait-for-aas (job) | nats-init (job) |
| `hvs-bearer-token` | hvs-aas-manager (Job) | HVS |
| `global-admin-generator-bearer-token` | global-admin-generator-aas-manager (Job) | Global Admin Generator |
| `nats-certs` | nats-init config map | nats |
| `trustagent-bearer-token` | trustagent-aas-manager (Job) | trustagent |

### **Attestation Persistent Volumes**

| Persistent Volume | Source Name | Consumer | Volume Mode | Comments |
|-------------------|-------------|----------|-------------|----------|
| `cms-base` | Created by CMS charts for PersistentVolume | CMS | File System | Volume mount to pod |
| `cms-logs` | Created by CMS charts for PersistentVolume | CMS | File System | Volume mount to pod |
| `aas-config` | Created by AAS charts for PersistentVolume | AAS | File System | Volume mount to pod |
| `aasdb` | Created by AAS DB charts for PersistentVolume | AAS DB | File System | Volume mount to pod |
| `aas-logs` | Created by AAS charts for PersistentVolume | AAS | File System | Volume mount to pod |
| `hvs-base` | Created by HVS charts for PersistentVolume | HVS | File System | Volume mount to pod |
| `hvsdb` | Created by HVS DB charts for PersistentVolume | HVS DB | File System | Volume mount to pod |
| `hvs-logs` | Created by HVS charts for PersistentVolume | HVS | File System | Volume mount to pod |


## **Complexity Assessment**

### **🔴 High Complexity Items**
 - Database Initialization Orchestration
   Complex startup dependencies with certificate management
 - Certificate/Secret Management
   Secure distribution of certificates and secrets
 - Privileged Container Configuration
   Ensuring proper host access and security context
 - Init Container Logic Migration
   Converting init container logic to Docker Compose equivalents
 - Complex certificate dependencies may cause startup failures

### **🟡 Medium Complexity Items**
- Service-to-service communication and discovery
- Kubernetes DNS vs Docker Compose DNS differences
- Volume mount configurations for persistent data
- Environment variable management and templating
- Health check implementation and dependency management

### **🟢 Low Complexity Items**
- Basic service containerization
- Network configuration
- Documentation and deployment scripts

### **Migration Path:**
1. **Parallel Deployment** - Run Docker Compose alongside Kubernetes initially
2. **Gradual Migration** - Move services incrementally
3. **Validation Testing** - Comprehensive testing at each stage

### **Service Implementation Order:**

1. **Attestation Manager**
2. **Trust Agent**
3. **Attestation Verifier Stack** (foundation services)
   - **CMS** (certificate authority)
   - **PostgreSQL databases** (aasdb, hvsdb)
   - **NATS** (messaging)
   - **AAS** (authentication)
   - **HVS** (verification)

## Task List

| Task # | Task Name | Status | Description | Duration |
|--------|-----------|--------|-------------|----------|
| 1 | Configuration and Environment Setup | Pending | Setup base configuration files, environment variables, and Docker Compose structure | 3 days |
| 2 | Attestation Manager Service Implementation | Pending | Implement Docker Compose service for Attestation Manager with proper dependencies | 3 days |
| 3 | Trust Agent Service Implementation | Pending | Implement privileged Trust Agent service with host access and volume mounts | 5 days |
| 4 | CMS (Certificate Management Service) Implementation | Pending | Implement certificate authority service with proper initialization | 5 days |
| 5 | PostgreSQL Databases Setup | Pending | Setup AAS and HVS databases with proper initialization and security | 5 days |
| 6 | NATS Messaging Service Implementation | Pending | Implement NATS messaging broker with certificate configuration | 5 days |
| 7 | AAS (Authentication & Authorization Service) Implementation | Pending | Implement authentication service with database connectivity | 3 days |
| 8 | HVS (Host Verification Service) Implementation | Pending | Implement host verification service with database and NATS integration | 3 days |
| 9 | Security and Secrets Management | Pending | Implement secure secret distribution and certificate management | 5 days |
| 10 | Deployment Scripts, packaging in standalone installer | Pending | Create deployment scripts and packaging for standalone installation | 3 days |
| 11 | End-to-End Testing and Validation | Pending | Comprehensive testing of complete attestation flow | 5 days |

**Total Estimated Duration:** 45 days

#### **Deployment Scripts:**
- `deploy-tc-docker.sh` - Master deployment script (all services)
   - setup environment function
        - `.env` - Environment variables for all services
        - `config/ima-policy` - IMA policy configuration
        - `config/ima-allowlist` - IMA allowlist for file integrity
   - call `docker-compose -f docker-compose.yml up -d`

#### **Docker Compose Files:**
- `docker-compose.yml` - Complete stack deployment
- `docker-compose-attestation-manager.yml` - Standalone Attestation Manager
- `docker-compose-trustagent.yml` - Standalone Trust Agent  
- `docker-compose-attestation-verifier.yml` - Attestation Verifier Stack


## **Success Criteria**

### **Functional Requirements:**
- [ ] All services start successfully with proper dependencies
- [ ] Certificate chain validation works end-to-end
- [ ] Database connections and schema initialization complete
- [ ] Trust agent can access required host resources
- [ ] Inter-service communication works correctly
- [ ] Attestation flow completes successfully

### **Non-Functional Requirements:**
- [ ] Startup time comparable to Kubernetes deployment
- [ ] Security posture maintained
- [ ] Deployment process is reproducible
- [ ] Update documentation is clear and comprehensive



