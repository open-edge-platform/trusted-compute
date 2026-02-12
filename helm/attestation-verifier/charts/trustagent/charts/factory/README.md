# Factory Lib Chart for Attestation-verifier Services & Agents

## Lib Chart details

Library charts provide useful utilities or functions for the chart developer. They're included as a dependency of application charts to inject those utilities and functions into the rendering pipeline

## Naming Convention
The naming convention for the `*.tpl` files is as follows

```
<fileName-without-underscore><function-name>
```
> **NOTE:** Some places the `<fileName-without-underscore>` might not be needed , e.g in `_names.tpl` the `<function-name>` itself is sufficient 

### `_env.tpl`

* `envCmsSha384` : Common env for CMS_TLS_SHA384

### `_headers.tpl`
* `headers` : Common Header for all files in helm charts

* `imageContainer` : Common container image for service containers
* `imageInitContainer` : Common container image for init container for service depedencies
* `imageDb` : Common container image for db containers 

### `_init.tpl`

* `initWaitForDb` : Common init container to wait for DB to be in ready state to accept connections
* `initWaitForCmsSha384BearerToken` : Common init container wait for CMS_TLS_SHA384 & BEARER_TOKEN


* `pvConfigCommonSpec` : Common persistent volume abstraction for config PVs
* `pvLogsCommonSpec` : Common persistent volume abstraction for logs PVs 
* `pvDbCommonSpec` : Common persistent volume abstraction for db PVs

### `_service.tpl`

* `serviceCommonSpec` : Common service abstraction for service.yaml
* `serviceDbCommonSpec` : Common service abstraction for db-service.yaml

### `_tolerationsAffinity.tpl`

* `tolerations` : Common toleration abstraction for Attestation-verifier-Extensions
* `affinity` : Common affinity abstraction for Attestation-verifier-Extensions

### `_volumeMounts.tpl`

* `volumeMountSecrets` : Common secret volume mounts for Services with/without DB as applicable
* `volumeMountsSvc` : Common volume mount abstraction for Services
* `volumeMountsSvcDb` : Common volume mount abstraction for Services with DB
* `volumeMountsDb` : Common volume mount abstraction for DB Service
* `volumeMountsExtensions` : Common volume mount abstraction for Attestation-verifier-Extensions

### `_volumes.tpl`

* `volumeDbCerts` : Common dbCerts volume abstraction for Services with and without DB as applicable
* `volumeCredentials` : Common credentials volume abstraction for Services with and without DB as applicable
* `volumeAasBearerToken` : Common BEARER_TOKEN volume abstraction for services dependent on BEARER_TOKEN
* `volumeAasBootstrapToken` : Common AAS_BOOTSTRAP_TOKEN volume abstraction for AAS service
* `volumek8sToken` : Common K8S_TOKEN volume abstraction for services requiring K8s API access
* `volumesSvc` : Common volume abstraction for Services
* `volumesSvcDb` :  Common volume abstraction for Service with DB
* `volumesSvcDbAas` : Common volume abstraction for AAS Service
* `volumesDb` : Common volume abstraction for DB Service
* `volumesExtensions` : Common volume abstraction for Attestation-verifier-Extensions
