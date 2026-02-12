{{/*
Job for getting user creation & roles
*/}}
{{- define "factory.createAASRolesAndPermissionSecret" -}}
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "factory.name" . }}-aas-json
  namespace: {{ .Release.Namespace }}
type: Opaque
data:
  #TODO: the aas-manager.json file needs to be updated for rest of the services
  populate-users.json: {{ tpl (.Files.Get "aas-manager.json") . | b64enc }}
{{- end -}}
