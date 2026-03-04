{{/*
Wait for Database bootstrap
*/}}
{{- define "factory.initWaitForDb" -}}
- name: wait-for-{{ include "factory.name" . }}db
  image: {{ .Values.image.db.name }}
  securityContext:
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
  command: ["/bin/sh", "-c"]
  args:
  - >
    i=0 &&
    while [ -z $(pg_isready -h {{ include "factory.name" . }}db.{{ .Release.Namespace }}.svc -p {{ .Values.config.dbPort }} -U {{ .Values.secret.dbUsername }} | grep "accepting connections") ] && [ $i -lt 5 ]; do  sleep 2; i=$((i+1)); echo "Waiting for {{ include "factory.name" . }} db connection..."; done &&
    if [ $i -eq 5 ]; then echo "Error: timeout exceeded for {{ include "factory.name" . }} db: wait-for-{{ include "factory.name" . }}db"; exit 1; fi
{{- end }}


{{/*
Wait for CMS-TLS-SHA384, BEARER-TOKEN
*/}}
{{- define "factory.initWaitForCmsSha384BearerToken" -}}
- name: wait-for-cms-sha384-bearer-token
  image: busybox:1.32
  securityContext:
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
  command: ["/bin/sh", "-c"]
  args:
  - >
    i=0 &&
    while [ -z $CMS_TLS_CERT_SHA384 ] && [ ! $(ls /etc/secrets/BEARER_TOKEN 2> /dev/null) ] && [ $i -lt 5 ]; do sleep 5; i=$((i+1)); done &&
    if [ $i -eq 5 ]; then echo "Error: timeout exceeded for init job: wait-for-cms-sha384-bearer-token"; exit 1; fi
  env:
    - name: CMS_TLS_CERT_SHA384
      valueFrom:
        secretKeyRef:
          name: cms-tls-cert-sha384
          key: CMS_TLS_CERT_SHA384
    - name: BEARER_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ include "factory.name" . }}-bearer-token
          key: BEARER_TOKEN
  volumeMounts:
    - name: {{ include "factory.name" . }}-secrets
      mountPath: /etc/secrets/
      readOnly: true
{{- end }}

{{/*
Reset service PV contents when DB credentials in config.yml do not match current secret values
*/}}
{{- define "factory.initResetPvOnDbCredMismatch" -}}
- name: reset-pv-on-db-cred-mismatch
  image: busybox:1.32
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
  env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: {{ include "factory.name" . }}db-credentials
          key: {{ .Values.config.envVarPrefix }}_DB_USERNAME
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "factory.name" . }}db-credentials
          key: {{ .Values.config.envVarPrefix }}_DB_PASSWORD
  command: ["/bin/sh", "-c"]
  args:
    - >
      set -e;
      CONFIG_FILE="/etc/{{ .Values.service.directoryName }}/config.yml";
      if [ ! -f "$CONFIG_FILE" ]; then
        echo "Config file not present, skipping credential mismatch cleanup";
        exit 0;
      fi;
      CFG_DB_USERNAME=$(awk '
        /^[[:space:]]*db:[[:space:]]*$/ {in_db=1; next}
        in_db && /^[^[:space:]]/ {in_db=0}
        in_db && /^[[:space:]]*username:[[:space:]]*/ {
          sub(/^[[:space:]]*username:[[:space:]]*/, "", $0);
          gsub(/["\047]/, "", $0);
          print $0;
          exit
        }
      ' "$CONFIG_FILE");
      CFG_DB_PASSWORD=$(awk '
        /^[[:space:]]*db:[[:space:]]*$/ {in_db=1; next}
        in_db && /^[^[:space:]]/ {in_db=0}
        in_db && /^[[:space:]]*password:[[:space:]]*/ {
          sub(/^[[:space:]]*password:[[:space:]]*/, "", $0);
          gsub(/["\047]/, "", $0);
          print $0;
          exit
        }
      ' "$CONFIG_FILE");
      if [ -z "$DB_USERNAME" ] || [ -z "$DB_PASSWORD" ] || [ -z "$CFG_DB_USERNAME" ] || [ -z "$CFG_DB_PASSWORD" ]; then
        echo "Credential values are incomplete, skipping cleanup";
        exit 0;
      fi;
      if [ "$CFG_DB_USERNAME" != "$DB_USERNAME" ] || [ "$CFG_DB_PASSWORD" != "$DB_PASSWORD" ]; then
        echo "DB credentials changed, purging PV contents";
        find "/etc/{{ .Values.service.directoryName }}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +;
        find "/var/log/{{ .Values.service.directoryName }}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +;
      else
        echo "DB credentials unchanged, skipping cleanup";
      fi
  volumeMounts:
    {{- include "factory.volumeMountSvcConfig" . | nindent 4 }}
    {{- include "factory.volumeMountSvcLogs" . | nindent 4 }}
    {{- include "factory.volumeMountsBasePv" . | nindent 4 }}
    {{- include "factory.volumeMountSecrets" . | nindent 4 }}
{{- end }}


{{/*
Associate db volume with appropriate version
*/}}
{{- define "factory.initCommonSpecLinkDBVolumes" -}}
- name: link-db-volumes
  image: busybox:1.32
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
  command: ["/bin/sh", "-c"]
  args:
    - >
      set -e;
      cd {{ .Values.service.directoryName }};
      mkdir -p {{.Chart.AppVersion }};
      chown -R 503:500 . {{.Chart.AppVersion }};
      chmod 775 . {{.Chart.AppVersion }};
      rm -rf db;
      rm -rf {{.Chart.AppVersion }}/db;
      mkdir -p {{.Chart.AppVersion }}/db;
      ln -sfn {{.Chart.AppVersion }}/db db;
      if [ -d {{.Chart.AppVersion }}/db ]; then
        chown -R 503:500 {{.Chart.AppVersion }}/db;
      fi
  volumeMounts:
    - name: {{ include "factory.name" . }}-base
      mountPath: /{{ .Values.service.directoryName }}/
{{- end }}

{{/*
Associate config and log volumes with appropriate version
*/}}
{{- define "factory.initCommonSpecLinkServiceVolumes" -}}
- name: link-volumes
  image: busybox:1.32
  command: ["/bin/sh", "-c"]
  args:
    - >
      cd {{ .Values.service.directoryName }} &&
      ln -sfT {{.Chart.AppVersion }}/config config &&
      if [ -d "{{.Chart.AppVersion }}/opt" ]; then ln -sfT {{.Chart.AppVersion }}/opt opt ; fi &&
      ln -sfT {{.Chart.AppVersion }}/logs logs
  volumeMounts:
    - name: {{ include "factory.name" . }}-base
      mountPath: /{{ .Values.service.directoryName }}/
{{- end }}

{{/*
Backup job for services
*/}}
{{- define "factory.backupService" -}}
- name: {{ include "factory.name" . }}-backup-job
  image: busybox:1.32
  command: ["/bin/sh", "-c"]
  {{- $dirName := .Values.service.directoryName }}
  {{- if .Values.global }}
  args:
    - >
      if [ -f "/{{ $dirName }}/{{.Chart.AppVersion }}/config/version" ]; then echo "already data backed up skipping..."; exit 0; fi &&
      ls /{{ $dirName }}/ &&
      mkdir -p /{{ $dirName }}/{{.Chart.AppVersion }} && mkdir -p /{{ $dirName }}/{{.Chart.AppVersion }}/logs &&
      {{- if not (.Values.global.dbVersionUpgrade) }}
      if [ -d "/{{ $dirName }}/{{.Values.global.currentVersion}}/db" ]; then
         cp -r /{{ $dirName }}/{{.Values.global.currentVersion}}/db /{{ $dirName }}/{{.Chart.AppVersion }}/db
      fi &&
      {{- end }}
      cp -r /{{ $dirName }}/{{.Values.global.currentVersion}}/config /{{ $dirName }}/{{.Chart.AppVersion }}/config &&
      if [ -d "/{{ $dirName }}/{{.Values.global.currentVersion}}/opt" ]; then
        cp -r /{{ $dirName }}/{{.Values.global.currentVersion}}/opt /{{ $dirName }}/{{.Chart.AppVersion }}/opt
      fi
  {{- else}}
  args:
    - >
      if [ -f "/{{ $dirName }}/{{.Chart.AppVersion }}/config/version" ]; then echo "already data backed up skipping..."; exit 0; fi &&
      ls /{{ $dirName }}/ &&
      mkdir -p /{{ $dirName }}/{{.Chart.AppVersion }} && mkdir -p /{{ $dirName }}/{{.Chart.AppVersion }}/logs &&
      {{- if not (.Values.dbVersionUpgrade) }}
      if [ -d "/{{ $dirName }}/{{.Values.currentVersion}}/db" ]; then
         cp -r /{{ $dirName }}/{{.Values.currentVersion}}/db /{{ $dirName }}/{{.Chart.AppVersion }}/db
      fi &&
      {{- end }}
      cp -r /{{ $dirName }}/{{.Values.currentVersion}}/config /{{ $dirName }}/{{.Chart.AppVersion }}/config &&
      if [ -d "/{{ $dirName }}/{{.Values.currentVersion}}/opt" ]; then
        cp -r /{{ $dirName }}/{{.Values.currentVersion}}/opt /{{ $dirName }}/{{.Chart.AppVersion }}/opt
      fi
  {{- end}}
  volumeMounts:
    - name: {{ include "factory.name" . }}-base
      mountPath: /{{ $dirName }}/
{{- end }}

{{/*
Wait job for service upgrades
*/}}
{{- define "factory.waitForUpgradeService" -}}
- name: {{ include "factory.name" . }}-wait-for-upgrade-job
  image: alpine/kubectl:1.34.1
  command: ["/bin/sh", "-c"]
  args:
    - >
      if [ ! -f "/{{ .Values.service.directoryName }}/{{.Chart.AppVersion }}/config/version" ]; then
         kubectl wait --for=condition=complete --timeout=2m job/{{ include "factory.name" . }}-upgrade -n {{ .Release.Namespace }}
         echo {{.Chart.AppVersion }} > /{{ .Values.service.directoryName }}/{{.Chart.AppVersion }}/config/version
      fi
  volumeMounts:
    - name: {{ include "factory.name" . }}-base
      mountPath: /{{ .Values.service.directoryName }}/
{{- end }}
