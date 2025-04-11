{{/*
Tolerations for K8s-extensions
*/}}
{{- define "factory.tolerations" -}}
{{- if .Values.global }}
- key: {{ .Values.global.controlPlaneLabel }}
{{- else }}
- key: {{ .Values.controlPlaneLabel }}
{{- end }}
  operator: Exists
  effect: NoSchedule
{{- end }}


{{/*
Match Expressions for K8s-extensions
*/}}
{{- define "factory.matchExpressionsExtensions" -}}
- matchExpressions:
  {{- if .Values.global }}
  - key: {{ .Values.global.controlPlaneLabel }}
  {{- else }}
  - key: {{ .Values.controlPlaneLabel }}
  {{- end }}
    operator: Exists
{{- end }}
   

{{/*
Match Expressions for Agents
*/}}
{{- define "factory.matchExpressionsAgents"}}
- matchExpressions:
  - key: node.type
    operator: In
{{- end }}


{{/*
Affinity for K8s-extensions
*/}}
{{- define "factory.affinityExtensions" -}}
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
      {{- include "factory.matchExpressionsExtensions" . | nindent 6 }}
{{- end }}


{{/*
Affinity for Agents
*/}}
{{- define "factory.affinityAgents" -}}
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
      {{- include "factory.matchExpressionsAgents" . | indent 6 }}
{{- end }}


