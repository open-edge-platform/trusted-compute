{{/*
PVC for config
*/}}
{{- define "factory.pvcConfigCommonSpec" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "factory.name" . }}-config
  namespace: {{ .Release.Namespace }}
spec:
{{- end }}

{{/*
PVC for logs
*/}}
{{- define "factory.pvcLogsCommonSpec" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "factory.name" . }}-logs
  namespace: {{ .Release.Namespace }}
spec:
{{- end }}

{{/*
PVC for Db
*/}}
{{- define "factory.pvcDbCommonSpec" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "factory.name" . }}db
  namespace: {{ .Release.Namespace }}
spec:
{{- end }}

{{/*
PVC for Base
*/}}
{{- define "factory.pvcBaseCommonSpec" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "factory.name" . }}-base
  namespace: {{ .Release.Namespace }}
spec:
{{- end }}

