
{{/*
PV for config
*/}}
{{- define "factory.pvConfigCommonSpec" -}}
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {{ include "factory.name" . }}-config
spec:
  capacity:
    storage: {{ .Values.storage.hostPath.configSize }}
  volumeMode: Filesystem
  accessModes:
    - {{ .Values.storage.hostPath.accessModes | join " " | quote }}
  persistentVolumeReclaimPolicy: {{ .Values.storage.hostPath.reclaimPolicy }}
  claimRef:
    namespace: {{ .Release.Namespace }}
    name: {{ include "factory.name" . }}-config
{{- end -}}


{{/*
PV for logs
*/}}
{{- define "factory.pvLogsCommonSpec" -}}
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {{ include "factory.name" . }}-logs
spec:
  capacity:
    storage: {{ .Values.storage.hostPath.logsSize }}
  volumeMode: Filesystem
  accessModes:
    - {{ .Values.storage.hostPath.accessModes | join " " | quote }}
  persistentVolumeReclaimPolicy: {{ .Values.storage.hostPath.reclaimPolicy }}
  claimRef:
    namespace: {{ .Release.Namespace }}
    name: {{ include "factory.name" . }}-logs
{{- end -}}


{{/*
PV for DB
*/}}
{{- define "factory.pvDbCommonSpec" -}}
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {{ include "factory.name" . }}db
spec:
  capacity:
    storage: {{ .Values.storage.hostPath.dbSize }}
  volumeMode: Filesystem
  accessModes:
    - {{ .Values.storage.hostPath.accessModes | join " " | quote }}
  persistentVolumeReclaimPolicy: {{ .Values.storage.hostPath.reclaimPolicy }}
  claimRef:
    namespace: {{ .Release.Namespace }}
    name: {{ include "factory.name" . }}db
{{- end -}}

{{/*
PV for DB
*/}}
{{- define "factory.pvBaseCommonSpec" -}}
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {{ include "factory.name" . }}-base
spec:
  capacity:
    storage: {{ .Values.storage.hostPath.baseSize }}
  volumeMode: Filesystem
  accessModes:
    - {{ .Values.storage.hostPath.accessModes | join " " | quote }}
  persistentVolumeReclaimPolicy: {{ .Values.storage.hostPath.reclaimPolicy }}
  claimRef:
    namespace: {{ .Release.Namespace }}
    name: {{ include "factory.name" . }}-base
{{- end -}}
