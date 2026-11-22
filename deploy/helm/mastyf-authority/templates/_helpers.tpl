{{- define "ma.name" -}}{{ .Release.Name }}{{- end -}}
{{- define "ma.tag" -}}{{ .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}{{- end -}}
{{- define "ma.labels" -}}
app.kubernetes.io/part-of: mastyf-authority
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ include "ma.tag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "ma.policyCM" -}}{{ .Values.policy.existingConfigMap | default (printf "%s-policy" .Release.Name) }}{{- end -}}
{{- define "ma.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: ["ALL"] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{- define "ma.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .Values.podSecurity.runAsUser }}
runAsGroup: {{ .Values.podSecurity.runAsUser }}
fsGroup: {{ .Values.podSecurity.fsGroup }}
seccompProfile: { type: RuntimeDefault }
{{- end -}}
