{{/*
Readiness Probe
*/}}
{{- define "factory.probeReadiness" -}}
exec:
  command:
  - cat
  - /etc/{{ .Values.service.directoryName }}/.setup_done
initialDelaySeconds: 5
failureThreshold: 60
periodSeconds: 15
{{- end }}