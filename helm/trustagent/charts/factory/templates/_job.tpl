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
      {{- if .Values.image.aasManager.imagePullSecret }}
      imagePullSecrets:
      - name: {{ .Values.image.aasManager.imagePullSecret }}
      {{- end }}
      serviceAccountName: {{ include "factory.name" . }}
      securityContext:
        {{- toYaml .Values.securityContext.aasManagerInit | nindent 8 }}
      restartPolicy: Never
      {{- if not (contains "Trusted-Workload-Placement-Cloud-Service-Provider" .Template.BasePath) }}
      initContainers:
        - name: {{ include "factory.name" . }}-wait-for-aas
          image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
          env:
            - name: URL
              value: https://{{ .Values.dependentServices.aas }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.aas.containerPort }}/aas/v1/version
            - name: VERSION
              value: {{.Chart.AppVersion }}         
            - name: DEPEDENT_SERVICE_NAME
              value: {{ .Values.dependentServices.aas }}
            - name: COMPONENT
              value: {{ include "factory.name" . }}
          securityContext:
            runAsUser: 503
            runAsGroup: 500
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
      {{- end }}
      containers:
        - name: {{ include "factory.name" . }}-aas-manager
          image: {{ .Values.image.aasManager.name }}:{{.Chart.AppVersion }}
          imagePullPolicy: {{ .Values.image.aasManager.pullPolicy }}
          securityContext:
            {{- toYaml .Values.securityContext.aasManager | nindent 12 }}
          env:
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
            {{- if .Values.image.aasManager.imagePullSecret }}
            imagePullSecrets:
              - name: {{ .Values.image.aasManager.imagePullSecret }}
            {{- end }}
            serviceAccountName: {{ include "factory.name" . }}
            securityContext:
              {{- toYaml .Values.securityContext.aasManagerInit | nindent 14 }}
            restartPolicy: Never
            {{- if not (contains "Trusted-Workload-Placement-Cloud-Service-Provider" .Template.BasePath) }}
            initContainers:
              - name: {{ include "factory.name" . }}-wait-for-aas
                image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
                env:
                    - name: URL
                      value: https://{{ .Values.dependentServices.aas }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.aas.containerPort }}/aas/v1/version
                    - name: VERSION
                      value: {{.Chart.AppVersion }}
                    - name: DEPEDENT_SERVICE_NAME
                      value: {{ .Values.dependentServices.aas }}
                    - name: COMPONENT
                      value: {{ include "factory.name" . }}
                securityContext:
                  {{- toYaml .Values.securityContext.aasManager | nindent 18 }}
            {{- end }}
            containers:
              - name: {{ include "factory.name" . }}-aas-manager
                image: {{ .Values.image.aasManager.name }}:{{.Chart.AppVersion }}
                imagePullPolicy: {{ .Values.image.aasManager.pullPolicy }}
                securityContext:
                  {{- toYaml .Values.securityContext.aasManager | nindent 18 }}
                env:
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
                  secretName: {{ include "factory.name" . }}-aas-manager-aas-json
{{- end -}}

{{/*
Job for db version upgrade
*/}}
{{- define "factory.dbVersionUpgrade" -}}
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
{{- end }}
