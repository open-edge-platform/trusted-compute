
Hvs
===========

A Helm chart for Installing Attestation-verifier-DC Host Verification Service


## Configuration

The following table lists the configurable parameters of the Hvs chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `nameOverride` | The name for HVS chart<br> (Default: `.Chart.Name`) | `""` |
| `controlPlaneHostname` | K8s control plane IP/Hostname<br> (**REQUIRED**) | `"<user input>"` |
| `versionUpgrade` | Set this true when performing upgrading to next minor/major version | `false` |
| `currentVersion` | Set the currently deployed version | `null` |
| `dependentServices.cms` |  | `"cms"` |
| `dependentServices.aas` |  | `"aas"` |
| `config.envVarPrefix` |  | `"HVS"` |
| `config.dbPort` | PostgreSQL DB port | `5432` |
| `config.dbSSL` | PostgreSQL DB SSL<br> (Allowed Values: `on`/`off`) | `"on"` |
| `config.dbSSLCert` | PostgreSQL DB SSL Cert | `"/etc/postgresql/secrets/server.crt"` |
| `config.dbSSLKey` | PostgreSQL DB SSL Key | `"/etc/postgresql/secrets/server.key"` |
| `config.dbSSLCiphers` | PostgreSQL DB SSL Ciphers | `"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"` |
| `config.dbListenAddresses` | PostgreSQL DB Listen Address | `"*"` |
| `config.dbName` | HVS DB Name | `"hvsdb"` |
| `config.dbSSLMode` | PostgreSQL DB SSL Mode | `"verify-full"` |
| `config.dbhostSSLPodRange` | PostgreSQL DB Host Address(IP address/subnet-mask). IP range varies for different k8s network plugins(Ex: Flannel - 10.1.0.0/8 (default), Calico - 192.168.0.0/16). | `"10.1.0.0/8"` |
| `config.dbMaxConnections` | Determines the maximum number of concurrent connections to the database server. Default is 200 | `200` |
| `config.dbSharedBuffers` | Determines how much memory is dedicated to PostgreSQL to use for caching data. Default is 2GB | `"2GB"` |
| `config.requireEKCertForHostProvision` | If set to true, worker node EK certificate should be registered in HVS DB, for AIK provisioning step of TA. (Allowed values: `true`\`false`) | `"<user input>"` |
| `config.verifyQuoteForHostRegistration` | If set to true, when the worker node is being registered to HVS, quote verification will be done. Default value is false. (Allowed values: `true`\`false`) | `"<user input>"` |
| `config.nats.enabled` | Enable/Disable NATS mode<br> (Allowed values: `true`\`false`) | `false` |
| `config.nats.servers` | NATS Server IP/Hostname | `""` |
| `config.nats.serviceMode` | The model for TA<br> (Allowed values: `outbound`) | `""` |
| `aas.url` |  | `null` |
| `aas.secret.adminUsername` | Admin Username for AAS | `null` |
| `aas.secret.adminPassword` | Admin Password for AAS | `null` |
| `secret.dbUsername` | DB Username for HVS DB | `null` |
| `secret.dbPassword` | DB Password for HVS DB | `null` |
| `secret.serviceUsername` | Admin Username for HVS | `null` |
| `secret.servicePassword` | Admin Password for HVS | `null` |
| `secret.installAdminUsername` | Admin Username for HVS | `null` |
| `secret.installAdminPassword` | Admin Password for HVS | `null` |
| `image.db.registry` | The image registry where PostgreSQL image is pulled from | `"dockerhub.io"` |
| `image.db.name` | The image name of PostgreSQL | `"postgres:14.2"` |
| `image.db.pullPolicy` | The pull policy for pulling from container registry for PostgreSQL image | `"Always"` |
| `image.svc.name` | The image name with which HVS image is pushed to registry<br> (**REQUIRED**) | `"<user input>"` |
| `image.svc.pullPolicy` | The pull policy for pulling from container registry for HVS<br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `image.svc.imagePullSecret` | The image pull secret for authenticating with image registry, can be left empty if image registry does not require authentication | `null` |
| `image.svc.initName` |  | `"<user input>"` |
| `image.aasManager.name` | The image registry where AAS Manager image is pushed<br> (**REQUIRED**) | `"<user input>"` |
| `image.aasManager.pullPolicy` | The pull policy for pulling from container registry for AAS Manager <br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `image.aasManager.imagePullSecret` | The image pull secret for authenticating with image registry, can be left empty if image registry does not require authentication | `null` |
| `storage.nfs.server` | The NFS Server IP/Hostname<br> (**REQUIRED**) | `"<user input>"` |
| `storage.nfs.reclaimPolicy` | The reclaim policy for NFS<br> (Allowed values: `Retain`/) | `"Retain"` |
| `storage.nfs.accessModes` | The access modes for NFS<br> (Allowed values: `ReadWriteMany`) | `"ReadWriteMany"` |
| `storage.nfs.path` | The path for storing persistent data on NFS | `"/mnt/nfs_share"` |
| `storage.nfs.dbSize` | The DB size for storing DB data for HVS in NFS path | `"5Gi"` |
| `storage.nfs.configSize` | The configuration size for storing config for HVS in NFS path | `"10Mi"` |
| `storage.nfs.logsSize` | The logs size for storing logs for HVS in NFS path | `"1Gi"` |
| `storage.nfs.baseSize` | The base volume size (configSize + logSize + dbSize) | `"6.1Gi"` |
| `securityContext.hvsdbInit.fsGroup` |  | `500` |
| `securityContext.hvsdb.runAsUser` |  | `503` |
| `securityContext.hvsdb.runAsGroup` |  | `500` |
| `securityContext.hvsInit.fsGroup` |  | `500` |
| `securityContext.hvs.runAsUser` |  | `503` |
| `securityContext.hvs.runAsGroup` |  | `500` |
| `securityContext.hvs.capabilities.drop` |  | `["all"]` |
| `securityContext.hvs.allowPrivilegeEscalation` |  | `false` |
| `securityContext.aasManager.runAsUser` |  | `503` |
| `securityContext.aasManager.runAsGroup` |  | `500` |
| `securityContext.aasManager.capabilities.drop` |  | `["all"]` |
| `securityContext.aasManager.allowPrivilegeEscalation` |  | `false` |
| `securityContext.aasManagerInit.fsGroup` |  | `500` |
| `service.directoryName` |  | `"hvs"` |
| `service.cms.containerPort` | The containerPort on which CMS can listen | `8445` |
| `service.aas.containerPort` | The containerPort on which AAS can listen | `8444` |
| `service.aas.port` | The externally exposed NodePort on which AAS can listen to external traffic | `30444` |
| `service.hvsdb.containerPort` | The containerPort on which HVS DB can listen | `5432` |
| `service.hvs.containerPort` | The containerPort on which HVS can listen | `8443` |
| `service.hvs.port` | The externally exposed NodePort on which HVS can listen to external traffic | `30443` |
| `service.ingress.enable` | Accept true or false to notify ingress rules are enable or disabled | `false` |



---
_Documentation generated by [Frigate](https://frigate.readthedocs.io)._

