{{/*
Common Deployment spec
*/}}
{{- define "factory.deploymentCommonSpec" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "factory.name" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
    {{- include "factory.labelsSvc" . | nindent 4 }}
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      {{- include "factory.labelsSvcSelector" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "factory.labelsSvcSelector" . | nindent 8 }}
{{- end }}


{{/*
Common DB Deployment spec
*/}}
{{- define "factory.deploymentDbCommonSpec" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "factory.name" . }}db
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
    {{- include "factory.labelsDb" . | nindent 4 }}
spec:
  strategy:
    type: Recreate
  replicas: 1
  selector:
    matchLabels:
      {{- include "factory.labelsDbSelector" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "factory.labelsDbSelector" . | nindent 8 }}
{{- end }}
