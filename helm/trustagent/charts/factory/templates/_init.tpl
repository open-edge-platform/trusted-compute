{{/*
Wait for Database bootstrap
*/}}
{{- define "factory.initWaitForDb" -}}
- name: wait-for-{{ include "factory.name" . }}db
  image: {{ .Values.image.db.name }}
  command: ["/bin/sh", "-c"]
  args:
  - >
    i=0 &&
    while [ -z $(pg_isready -h {{ include "factory.name" . }}db.{{ .Release.Namespace }}.svc.cluster.local -p {{ .Values.config.dbPort }} -U {{ .Values.secret.dbUsername }} | grep "accepting connections") ] && [ $i -lt 5 ]; do  sleep 2; i=$((i+1)); echo "Waiting for {{ include "factory.name" . }} db connection..."; done &&
    if [ $i -eq 5 ]; then echo "Error: timeout exceeded for {{ include "factory.name" . }} db: wait-for-{{ include "factory.name" . }}db"; exit 1; fi
{{- end }}


{{/*
Wait for CMS-TLS-SHA384, BEARER-TOKEN
*/}}
{{- define "factory.initWaitForCmsSha384BearerToken" -}}
- name: wait-for-cms-sha384-bearer-token
  image: busybox:1.32
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
Associate db volume with appropriate version
*/}}
{{- define "factory.initCommonSpecLinkDBVolumes" -}}
- name: link-db-volumes
  image: busybox:1.32
  command: ["/bin/sh", "-c"]
  args:
    - >
      cd {{ .Values.service.directoryName }} && ln -sfT {{.Chart.AppVersion }}/db db
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
  volumeMounts:
    - name: {{ include "factory.name" . }}-base
      mountPath: /{{ $dirName }}/
{{- end }}

{{/*
Wait job for service upgrades
*/}}
{{- define "factory.waitForUpgradeService" -}}
- name: {{ include "factory.name" . }}-wait-for-upgrade-job
  image: bitnami/kubectl:1.23
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
