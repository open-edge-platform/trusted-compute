{{/*
Service
*/}}
{{- define "factory.serviceCommonSpec" -}}
kind: Service
apiVersion: v1
metadata:
  name: {{ include "factory.name" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
    {{- include "factory.labelsSvc" . | nindent 4 }}
spec:
  selector:
    {{- include "factory.labelsSvcSelector" . | nindent 4 }}
{{- end -}}


{{/*
DB Service
*/}}
{{- define "factory.serviceDbCommonSpec" -}}
kind: Service
apiVersion: v1
metadata:
  name: {{ include "factory.name" . }}db
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsDbSelector" . | nindent 4 }}
spec:
  selector:
    {{- include "factory.labelsDbSelector" . | nindent 4 }}
{{- end -}}