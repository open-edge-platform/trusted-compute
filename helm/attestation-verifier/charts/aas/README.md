
Aas
===========

A Helm chart for Installing Attestation Verifier Authentication and Authorization Service


## Configuration

The following table lists the configurable parameters of the Aas chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `nameOverride` | The name for AAS chart<br> (Default: `.Chart.Name`) | `""` |
| `controlPlaneHostname` | K8s control plane IP/Hostname<br> (**REQUIRED**) | `"<user input>"` |
| `versionUpgrade` | Set this true when performing upgrading to next minor/major version | `false` |
| `currentVersion` | Set the currently deployed version | `null` |
| `dependentServices.cms` |  | `"cms"` |
| `config.envVarPrefix` |  | `"AAS"` |
| `config.dbPort` | PostgreSQL DB port | `5432` |
| `config.dbSSL` | PostgreSQL DB SSL<br> (Allowed: `on`/`off`) | `"on"` |
| `config.dbSSLCert` | PostgreSQL DB SSL Cert | `"/etc/postgresql/secrets/server.crt"` |
| `config.dbSSLKey` | PostgreSQL DB SSL Key | `"/etc/postgresql/secrets/server.key"` |
| `config.dbSSLCiphers` | PostgreSQL DB SSL Ciphers | `"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"` |
| `config.dbListenAddresses` | PostgreSQL DB Listen Address | `"*"` |
| `config.dbName` | AAS DB Name | `"aasdb"` |
| `config.dbSSLMode` | PostgreSQL DB SSL Mode | `"verify-full"` |
| `config.dbhostSSLPodRange` | PostgreSQL DB Host Address(IP address/subnet-mask). IP range varies for different k8s network plugins(Ex: Flannel - 10.1.0.0/8 (default), Calico - 192.168.0.0/16). | `"10.1.0.0/8"` |
| `config.createCredentials` | Trigger to run create-credentials setup task when set to True. Default is False | `true` |
| `config.dbMaxConnections` | Determines the maximum number of concurrent connections to the database server. Default is 200 | `200` |
| `config.dbSharedBuffers` | Determines how much memory is dedicated to PostgreSQL to use for caching data. Default is 2GB | `"2GB"` |
| `secret.dbUsername` | DB Username for AAS DB | `null` |
| `secret.dbPassword` | DB Password for AAS DB | `null` |
| `secret.adminUsername` | Admin Username for AAS | `null` |
| `secret.adminPassword` | Admin Password for AAS | `null` |
| `image.db.registry` | The image registry where PostgreSQL image is pulled from | `"dockerhub.io"` |
| `image.db.name` | The image name of PostgreSQL | `"postgres:14.2"` |
| `image.db.pullPolicy` | The pull policy for pulling from container registry for PostgreSQL image<br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `image.svc.name` | The image name with which AAS image is pushed to registry | `"<user input>"` |
| `image.svc.pullPolicy` | The pull policy for pulling from container registry for AAS<br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `image.svc.imagePullSecret` | The image pull secret for authenticating with image registry, can be left empty if image registry does not require authentication | `null` |
| `image.svc.initName` | The image name of init container | `"<user input>"` |
| `storage.nfs.server` | The NFS Server IP/Hostname | `"<user input>"` |
| `storage.nfs.reclaimPolicy` | The reclaim policy for NFS<br> (Allowed values: `Retain`/) | `"Retain"` |
| `storage.nfs.accessModes` | The access modes for NFS<br> (Allowed values: `ReadWriteMany`) | `"ReadWriteMany"` |
| `storage.nfs.path` | The path for storing persistent data on NFS | `"/mnt/nfs_share"` |
| `storage.nfs.dbSize` | The DB size for storing DB data for AAS in NFS path | `"1Gi"` |
| `storage.nfs.configSize` | The configuration size for storing config for AAS in NFS path | `"10Mi"` |
| `storage.nfs.logsSize` | The logs size for storing logs for AAS in NFS path | `"1Gi"` |
| `storage.nfs.baseSize` | The base volume size (configSize + logSize + dbSize) | `"2.1Gi"` |
| `securityContext.aasdbInit.fsGroup` |  | `500` |
| `securityContext.aasdb.runAsUser` |  | `503` |
| `securityContext.aasdb.runAsGroup` |  | `500` |
| `securityContext.aasInit.fsGroup` |  | `500` |
| `securityContext.aas.runAsUser` |  | `503` |
| `securityContext.aas.runAsGroup` |  | `500` |
| `securityContext.aas.capabilities.drop` |  | `["all"]` |
| `securityContext.aas.allowPrivilegeEscalation` |  | `false` |
| `service.directoryName` |  | `"authservice"` |
| `service.cms.containerPort` | The containerPort on which CMS can listen | `8445` |
| `service.cms.port` | The externally exposed NodePort on which CMS can listen to external traffic | `30445` |
| `service.aasdb.containerPort` | The containerPort on which AAS DB can listen | `5432` |
| `service.aas.containerPort` | The containerPort on which AAS can listen | `8444` |
| `service.aas.port` | The externally exposed NodePort on which AAS can listen to external traffic | `30444` |
| `service.ingress.enable` | Accept true or false to notify ingress rules are enable or disabled | `false` |



---
_Documentation generated by [Frigate](https://frigate.readthedocs.io)._

