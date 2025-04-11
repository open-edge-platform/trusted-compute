{{/*
Common Daemonset header spec
*/}}
{{- define "factory.daemonSetCommonHeaderSpec"}}
apiVersion: apps/v1
kind: DaemonSet
{{- end -}}

{{/*
Common Daemonset spec
*/}}
{{- define "factory.daemonSetCommonSpec"}}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "factory.labelsChart" . | nindent 4 }}
    {{- include "factory.labelsSvc" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "factory.labelsSvcSelector" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "factory.labelsSvcSelector" . | nindent 8 }}
{{- end -}}