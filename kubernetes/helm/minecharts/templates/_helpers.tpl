{{- define "minecharts.name" -}}
{{- default .Chart.Name .Values.nameOverride -}}
{{- end -}}

{{- define "minecharts.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "minecharts.namespace" -}}
{{- if and .Values.namespace .Values.namespace.name -}}
{{- .Values.namespace.name -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{- define "minecharts.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "minecharts.labels" -}}
app.kubernetes.io/name: {{ include "minecharts.name" . }}
helm.sh/chart: {{ include "minecharts.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "minecharts.selectorLabels" -}}
app.kubernetes.io/name: {{ include "minecharts.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "minecharts.api.fullname" -}}
{{- if .Values.api.fullnameOverride -}}
{{- .Values.api.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-api" (include "minecharts.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "minecharts.web.fullname" -}}
{{- if .Values.web.fullnameOverride -}}
{{- .Values.web.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-web" (include "minecharts.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "minecharts.api.appLabel" -}}
{{- default (include "minecharts.api.fullname" .) .Values.api.appLabel -}}
{{- end -}}

{{- define "minecharts.web.appLabel" -}}
{{- default (include "minecharts.web.fullname" .) .Values.web.appLabel -}}
{{- end -}}

{{- define "minecharts.api.serviceName" -}}
{{- include "minecharts.api.fullname" . -}}
{{- end -}}

{{- define "minecharts.web.serviceName" -}}
{{- include "minecharts.web.fullname" . -}}
{{- end -}}

{{- define "minecharts.middlewareName" -}}
{{- default (printf "%s-api-strip" (include "minecharts.fullname" .)) .Values.middleware.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "minecharts.middlewareRef" -}}
{{- printf "%s-%s@kubernetescrd" (include "minecharts.namespace" .) (include "minecharts.middlewareName" .) -}}
{{- end -}}
