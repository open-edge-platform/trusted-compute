{{/*
Job for getting user creation & roles
*/}}
{{- define "factory.getAasUserAndRoles" -}}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "factory.name" . }}-aas-manager
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
spec:
  template:
    metadata:
      labels:
        {{- include "factory.labelsChart" . | nindent 8 }}
    spec:
      {{- if .Values.global }}
      {{- if .Values.global.image.imagePullSecret }}
      imagePullSecrets:
      - name: {{ .Values.global.image.imagePullSecret }}
      {{- end }}
      {{- else }}
      {{- if .Values.image.aasManager.imagePullSecret }}
      imagePullSecrets:
      - name: {{ .Values.image.aasManager.imagePullSecret }}
      {{- end }}
      {{- end }}
      serviceAccountName: {{ include "factory.name" . }}
      securityContext:
        {{- toYaml .Values.securityContext.aasManagerInit | nindent 8 }}
      restartPolicy: Never
      {{- if not (contains "Trusted-Workload-Placement-Cloud-Service-Provider" .Template.BasePath) }}
      initContainers:
        - name: {{ include "factory.name" . }}-wait-for-aas
        {{- if .Values.global }}
          image: {{ .Values.global.image.initName }}:{{.Chart.AppVersion }}
        {{- else }}
          image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
        {{- end }}
          env:
            {{- if .Values.global }}
              {{- if .Values.global.proxyEnabled }}
              {{- include "factory.globalProxy" . | nindent 12 }}
              {{- end }}
            {{- end }}
            - name: URL
              value: https://{{ .Values.dependentServices.aas }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.aas.containerPort }}/aas/v1/version
            - name: VERSION
              value: {{.Chart.AppVersion }}
            - name: DEPENDENT_SERVICE_NAME
              value: {{ .Values.dependentServices.aas }}
            - name: COMPONENT
              value: {{ include "factory.name" . }}
          securityContext:
            runAsUser: 0
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
      {{- end }}
      {{- include "factory.hostAliases" . | nindent 6 | trim}}
      containers:
        - name: {{ include "factory.name" . }}-aas-manager
        {{- if .Values.global }}
          image: {{ .Values.global.image.aasManagerName }}:{{.Chart.AppVersion }}
        {{- else }}
          image: {{ .Values.image.aasManager.name }}:{{.Chart.AppVersion }}
        {{- end }}
        {{- if .Values.global }}
          imagePullPolicy: {{ .Values.global.image.pullPolicy }}
        {{- else }}
          imagePullPolicy: {{ .Values.image.aasManager.pullPolicy }}
        {{- end }}
          securityContext:
            {{- toYaml .Values.securityContext.aasManager | nindent 12 }}
          env:
            {{- if .Values.global }}
              {{- if .Values.global.proxyEnabled }}
              {{- include "factory.globalProxy" . | nindent 12 }}
              {{- end }}
            {{- end }}
          command: ["/bin/sh", "-c"]
          args:
            - >
              echo starting &&
              BEARER_TOKEN=$(populate-users --use_json=true --in_json_file=/etc/secrets/populate-users.json | grep BEARER_TOKEN | cut -d '=' -f2) &&
              if [ -z "$BEARER_TOKEN" ]; then exit 1; fi &&
              INSTALLATION_TOKEN=`echo $BEARER_TOKEN | cut -d " " -f1` &&
              if [ -z "$INSTALLATION_TOKEN" ]; then exit 1; fi &&
              ./kubectl delete secret {{ include "factory.name" . }}-bearer-token -n {{ .Release.Namespace }} --ignore-not-found  &&
              ./kubectl create secret generic {{ include "factory.name" . }}-bearer-token -n {{ .Release.Namespace }} --from-literal=BEARER_TOKEN=$INSTALLATION_TOKEN &&
              exit 0
          volumeMounts:
            - name: {{ include "factory.name" . }}-aas-json
              mountPath: /etc/secrets/
              readOnly: true
      volumes:
        - name: {{ include "factory.name" . }}-aas-json
          secret:
            secretName: {{ include "factory.name" . }}-aas-json
{{- end -}}
{{- define "factory.getAasUserAndRolesForDaemonsets" -}}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ include "factory.name" . }}-aas-manager
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
spec:
  schedule: "*/2 * * * *"
  successfulJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            {{- include "factory.labelsChart" . | nindent 12 }}
        spec:
          {{- if .Values.global }}
            {{- if .Values.global.image.imagePullSecret }}
            imagePullSecrets:
              - name: {{ .Values.global.image.imagePullSecret }}
            {{- end }}
            {{- else }}
            {{- if .Values.image.aasManager.imagePullSecret }}
            imagePullSecrets:
              - name: {{ .Values.image.aasManager.imagePullSecret }}
            {{- end }}
            {{- end }}
            serviceAccountName: {{ include "factory.name" . }}
            securityContext:
              {{- toYaml .Values.securityContext.aasManagerInit | nindent 14 }}
            restartPolicy: Never
            {{- if not (contains "Trusted-Workload-Placement-Cloud-Service-Provider" .Template.BasePath) }}
            initContainers:
              - name: {{ include "factory.name" . }}-wait-for-aas
              {{- if .Values.global }}
                image: {{ .Values.global.image.initName }}:{{.Chart.AppVersion }}
              {{- else }}
                image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
              {{- end }}
                env:
                  {{- if .Values.global }}
                    {{- if .Values.global.proxyEnabled }}
                    {{- include "factory.globalProxy" . | nindent 20 }}
                    {{- end }}
                    {{- end }}
                    - name: URL
                      value: https://{{ .Values.dependentServices.aas }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.aas.containerPort }}/aas/v1/version
                    - name: VERSION
                      value: {{.Chart.AppVersion }}
                    - name: DEPENDENT_SERVICE_NAME
                      value: {{ .Values.dependentServices.aas }}
                    - name: COMPONENT
                      value: {{ include "factory.name" . }}
            {{- end }}
            {{- include "factory.hostAliases" . | nindent 6 }}
            containers:
              - name: {{ include "factory.name" . }}-aas-manager
              {{- if .Values.global }}
                image: {{ .Values.global.image.aasManagerName }}:{{.Chart.AppVersion }}
              {{- else }}
                image: {{ .Values.image.aasManager.name }}:{{.Chart.AppVersion }}
              {{- end }}
              {{- if .Values.global }}
                imagePullPolicy: {{ .Values.global.image.pullPolicy }}
              {{- else }}
                imagePullPolicy: {{ .Values.image.aasManager.pullPolicy }}
              {{- end }}
                securityContext:
                  {{- toYaml .Values.securityContext.aasManager | nindent 18 }}
                env:
                  {{- if .Values.global }}
                  {{- if .Values.global.proxyEnabled }}
                  {{- include "factory.globalProxy" . | nindent 20 }}
                  {{- end }}
                  {{- end }}
                command: ["/bin/sh", "-c"]
                args:
                  - >
                    echo starting &&
                    BEARER_TOKEN=$(populate-users --use_json=true --in_json_file=/etc/secrets/populate-users.json | grep BEARER_TOKEN | cut -d '=' -f2) &&
                    if [ -z "$BEARER_TOKEN" ]; then exit 1; fi &&
                    INSTALLATION_TOKEN=`echo $BEARER_TOKEN | cut -d " " -f1` &&
                    if [ -z "$INSTALLATION_TOKEN" ]; then exit 1; fi &&
                    ./kubectl delete secret {{ include "factory.name" . }}-bearer-token -n {{ .Release.Namespace }} --ignore-not-found  &&
                    ./kubectl create secret generic {{ include "factory.name" . }}-bearer-token -n {{ .Release.Namespace }} --from-literal=BEARER_TOKEN=$INSTALLATION_TOKEN &&
                    exit 0
                volumeMounts:
                  - name: {{ include "factory.name" . }}-aas-json
                    mountPath: /etc/secrets/
                    readOnly: true
            volumes:
              - name: {{ include "factory.name" . }}-aas-json
                secret:
                  secretName: {{ include "factory.name" . }}-aas-json
{{- end -}}

{{/*
Job for db version upgrade
*/}}
{{- define "factory.dbVersionUpgrade" -}}
{{- if .Values.global }}
  {{- if .Values.global.dbVersionUpgrade }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "factory.name" . }}-db-version-upgrade
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
  annotations:
    "helm.sh/hook": pre-upgrade
    "helm.sh/hook-weight": "-4"
spec:
  template:
    metadata:
      labels:
        {{- include "factory.labelsChart" . | nindent 8 }}
    spec:
      {{- if .Values.global.image.imagePullSecret }}
      imagePullSecrets:
        - name: {{ .Values.global.image.imagePullSecret }}
      {{- end }}
      serviceAccountName: {{ include "factory.name" . }}
      restartPolicy: Never
      containers:
        - name: {{ include "factory.name" . }}-db-upgrade
          image: {{ .Values.global.image.dbVersionUpgradeImage }}
          env:
            - name: PGDATAOLD
              value: "/{{ .Values.service.directoryName }}/{{.Values.global.currentVersion}}/db"
            - name: PGDATANEW
              value: "/{{ .Values.service.directoryName }}/{{.Chart.AppVersion }}/db"
            {{- include "factory.envPostgres" . | nindent 12 }}
          volumeMounts:
            - name: {{ include "factory.name" . }}-base
              mountPath: /{{ .Values.service.directoryName }}/
            {{- include "factory.volumeMountsSvcDbUpgrade" . | nindent 12 }}
      volumes:
        {{- include "factory.volumesBasePV" . | nindent 8 }}
        {{- include "factory.volumesSvcDbCredentials" . | nindent 8 }}
  {{- end}}
  {{- else}}
  {{- if .Values.dbVersionUpgrade }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "factory.name" . }}-db-version-upgrade
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
  annotations:
    "helm.sh/hook": pre-upgrade
    "helm.sh/hook-weight": "-4"
spec:
  template:
    metadata:
      labels:
        {{- include "factory.labelsChart" . | nindent 8 }}
    spec:
      {{- if .Values.image.svc.imagePullSecret }}
      imagePullSecrets:
        - name: {{ .Values.image.svc.imagePullSecret }}
      {{- end }}
      serviceAccountName: {{ include "factory.name" . }}
      restartPolicy: Never
      containers:
        - name: {{ include "factory.name" . }}-db-upgrade
          image: {{ .Values.image.db.dbVersionUpgradeImage }}
          env:
            - name: PGDATAOLD
              value: "/{{ .Values.service.directoryName }}/{{.Values.currentVersion}}/db"
            - name: PGDATANEW
              value: "/{{ .Values.service.directoryName }}/{{.Chart.AppVersion }}/db"
            {{- include "factory.envPostgres" . | nindent 12 }}
          volumeMounts:
            - name: {{ include "factory.name" . }}-base
              mountPath: /{{ .Values.service.directoryName }}/
            {{- include "factory.volumeMountsSvcDbUpgrade" . | nindent 12 }}
      volumes:
          {{- include "factory.volumesSvcDbCredentials" . | nindent 8 }}
          {{- include "factory.volumesBasePV" . | nindent 8 }}
  {{- end}}
  {{- end}}
{{- end }}
